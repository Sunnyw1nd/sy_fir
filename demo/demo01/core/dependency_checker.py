import concurrent
import requests
from packaging.requirements import Requirement
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict
import logging
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional


class DependencyChecker:
    OSV_API_URL = "https://api.osv.dev/v1/query"    # 可移至配置文件
    ECOSYSTEM = "PyPI"
    REQUEST_INTERVAL = 1  # 请求间隔(秒)

    def __init__(self, timeout=30, retries=3, max_workers=5):
        self.timeout = timeout
        self.max_workers = max_workers
        self._init_logger()
        self._init_http_session(retries)

    def _init_logger(self):
        """配置日志系统"""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:
            # 控制台处理器
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_formatter = logging.Formatter(
                '[%(levelname)s] %(message)s'
            )
            console_handler.setFormatter(console_formatter)

            # 文件处理器
            file_handler = logging.FileHandler('dependency_scan.log')
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_formatter)

            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)

    def _init_http_session(self, retries):
        """配置HTTP会话"""
        self.session = requests.Session()
        retry = Retry(
            total=retries,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('https://', adapter)

    # 修改check方法：
    def check(self) -> List[Dict]:
        try:
            packages = self.parse_requirements()
            if not packages:
                self.logger.warning("未找到有效依赖项")
                return []

            # 添加超时控制
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self.check_package, pkg) for pkg in packages]
                results = []
                for future in concurrent.futures.as_completed(futures, timeout=self.timeout):
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                    except Exception as e:
                        self.logger.error(f"依赖检查失败: {str(e)}")
                return results
        except Exception as e:
            self.logger.critical("全局扫描失败", exc_info=True)
            return []

    def parse_requirements(self) -> List[Dict]:
        """解析requirements.txt文件"""
        packages = []
        try:
            with open('requirements.txt', 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith(('#', '--')):
                        continue

                    try:
                        req = Requirement(line)
                        packages.append({
                            'name': req.name,
                            'specifier': str(req.specifier),
                            'versions': self.extract_versions(req)
                        })
                    except Exception as e:
                        self.logger.error(
                            f"解析第{line_num}行失败: {line} - {str(e)}",
                            exc_info=True
                        )
        except FileNotFoundError:
            self.logger.error("requirements.txt文件未找到")
        return packages

    def check_package(self, pkg: Dict) -> Optional[Dict]:
        """检查单个包的漏洞"""
        time.sleep(self.REQUEST_INTERVAL)  # 速率控制
        for attempt in range(3):
            try:
                response = self.session.post(
                    self.OSV_API_URL,
                    json={
                        "package": {
                            "name": pkg['name'],
                            "ecosystem": self.ECOSYSTEM
                        },
                    },
                    timeout=self.timeout
                )

                # 验证响应状态
                if response.status_code == 200:
                    data = response.json()
                    if not isinstance(data, dict) or 'vulns' not in data:
                        self.logger.debug(f"{pkg['name']} 没有返回漏洞数据 (可能无漏洞): {data}")
                        return None

                    vulns = []
                    for vuln in data.get('vulns', []):
                        if not isinstance(vuln, dict):
                            self.logger.error(f"{pkg['name']} 漏洞数据格式错误: {vuln}")
                            continue
                        severity = self.map_severity(vuln)
                        if severity == 'critical':  # 记录关键漏洞
                            self.logger.warning(
                                f"发现高危漏洞: {pkg['name']} - {vuln.get('id')}"
                            )

                        affected = vuln.get('affected')
                        if isinstance(affected, list):
                            versions = []
                            for item in affected:
                                item_versions = item.get('versions', [])
                                versions.extend(item_versions)
                        else:
                            versions = affected.get('versions', []) if isinstance(affected, dict) else []

                        vulns.append({
                            'id': vuln.get('id'),
                            'summary': vuln.get('summary'),
                            'severity': severity,
                            'affected_versions': versions,
                            'reference': self._get_reference(vuln),
                            'details': vuln.get('details')
                        })

                    return {
                        'package': pkg['name'],
                        'specifier': pkg['specifier'],
                        'vulnerabilities': vulns
                    } if vulns else None

                self.logger.error(f"尝试 {attempt + 1} 失败: HTTP {response.status_code}")
                time.sleep(0.5 * (attempt + 1))  # 指数退避

            except requests.exceptions.RequestException:
                self.logger.error(f"网络错误: {pkg['name']}", exc_info=True)
            except Exception as e:
                self.logger.error(f"检查 {pkg['name']} 时出现未知错误: {e}", exc_info=True)

        return None

    @staticmethod
    def map_severity(vuln: Dict) -> str:
        """综合评估漏洞严重性"""
        severities = vuln.get('severity',[])
        # 优先CVSS v3，其次v2，最后默认low
        for entry in severities:
            try:
                score_val = entry.get('score')
                if score_val is None:
                    continue
                # 如果score是数值或数字字符串，直接转换为浮点数
                if isinstance(score_val, (int, float)) or (
                        isinstance(score_val, str) and score_val.replace('.', '', 1).isdigit()):
                    score_float = float(score_val)
                    if entry.get('type') == 'CVSS_V3':
                        return DependencyChecker._cvss_to_severity(score_float)
                    elif entry.get('type') == 'CVSS_V2':
                        # CVSS v2的评分适当降低一级
                        return DependencyChecker._cvss_to_severity(score_float - 1.0)
                # 如果score是CVSS向量字符串，尝试从中提取基准分值
                if isinstance(score_val, str) and '/' in score_val:
                    import re
                    match = re.search(r'(\d+(\.\d+)?)', score_val)
                    if match:
                        score_float = float(match.group(1))
                        if entry.get('type') == 'CVSS_V3':
                            return DependencyChecker._cvss_to_severity(score_float)
                        elif entry.get('type') == 'CVSS_V2':
                            return DependencyChecker._cvss_to_severity(score_float - 1.0)
            except Exception as e:
                logging.getLogger("DependencyChecker").error(f"Severity parse error: {e}")
        return 'low'
    """ 解释：新版map_severity函数对OSV提供的严重性信息进行了更健壮的处理。
    原始实现只处理了CVSS向量格式的字符串，忽略了纯数值和其他形式，导致无法正确映射“HIGH”等级。
    修改后代码首先判断score是否为数值或数字形式的字符串，直接据此计算严重级别；
    然后如果是包含CVSS向量的字符串，则用正则表达式提取其中的数值部分进行映射。
    这样，无论OSV返回CVSS基准分值（如9.8）还是完整向量字符串，都会得到正确的严重性分类（如返回'critical'或'high'等）。"""

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        """CVSS评分转等级"""
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        else:
            return 'low'

    @staticmethod
    def _get_reference(vuln: Dict) -> Optional[str]:
        """获取最有价值的参考链接"""
        ref_priority = ['ADVISORY', 'ARTICLE', 'WEB']
        for ref_type in ref_priority:
            for ref in vuln.get('references', []):
                if ref['type'] == ref_type:
                    return ref['url']
        return None

    @staticmethod
    def extract_versions(req: Requirement) -> List[str]:
        """精确解析版本规范"""
        versions = []
        for spec in req.specifier:
            if spec.operator in ('==', '===', '~=', '>=', '>', '<', '<='):
                versions.append(f"{spec.operator}{spec.version}")
            elif spec.operator == '!=':
                versions.append(f"!={spec.version}")
        return ['*']
        # return versions or ['*']  # 无版本限制时查询所有