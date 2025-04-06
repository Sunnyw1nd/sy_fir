from urllib.parse import urlparse
import nmap
import socket
from typing import List, Dict
import os
import platform
from colorama import init, Fore


class PortScanner:
    HIGH_RISK_PORTS = {
        21: ('FTP', '高危'),
        22: ('SSH', '中危'),
        23: ('Telnet', '高危'),
        80: ('HTTP', '低危'),
        443: ('HTTPS', '低危'),
        445: ('SMB', '严重'),
        3389: ('RDP', '高危'),
        6379: ('Redis', '高危'),
        27017: ('MongoDB', '高危'),
        3306: ('MySQL', '高危'),
        5432: ('PostgreSQL', '高危'),
        5900: ('VNC', '高危')
    }

    def __init__(self, ports: str = "1-1000", scan_type: str = "syn", timeout: int = 120, dashboard=None):
        self.nm = nmap.PortScanner()
        self.ports = ports
        self.scan_type = self._validate_scan_type(scan_type)
        self.timeout = timeout
        self.dashboard = dashboard
        self.task_id = None
        self._check_privileges()
        init(autoreset=True)

    def scan(self, target: str) -> List[Dict]:
        parsed = urlparse(target)
        if parsed.hostname:
            target = parsed.hostname

        if not self._validate_target(target):
            return []

        try:
            scan_args = self._build_scan_arguments()
            self.nm.scan(hosts=target, ports=self.ports, arguments=scan_args, timeout=self.timeout)
            return self._parse_results(target)
        except nmap.PortScannerError as e:
            print(Fore.RED + f"[ERROR] 扫描失败: {str(e)}")
            return []
        except Exception as e:
            print(Fore.RED + f"[CRITICAL] 未知错误: {str(e)}")
            return []

    def _build_scan_arguments(self) -> str:
        args = []
        if self.scan_type == "syn":
            args.append("-sS")
        elif self.scan_type == "connect":
            args.append("-sT")
        elif self.scan_type == "udp":
            args.append("-sU")

        args.extend(["-sV", f"--host-timeout {self.timeout}s", "--max-retries 2", "--min-rate 500", "-T4"])
        return ' '.join(args)

    def _parse_results(self, target: str) -> List[Dict]:
        results = []
        try:
            host_info = self.nm[target]
        except KeyError:
            return results

        count = 0
        total = sum(len(host_info[proto].keys()) for proto in host_info.all_protocols())
        if self.dashboard:
            self.task_id = self.dashboard.add_task("端口扫描", total=total)

        for proto in host_info.all_protocols():
            for port in host_info[proto].keys():
                count += 1
                port_info = host_info[proto][port]
                if port_info['state'] != 'open':
                    if self.dashboard:
                        self.dashboard.update(self.task_id, advance=1)
                    continue

                risk_info = self.HIGH_RISK_PORTS.get(port, (port_info['name'], '低危'))
                service = port_info.get('product', risk_info[0])
                version = port_info.get('version', '')
                cpe = port_info.get('cpe', '')

                results.append({
                    'type': 'port',
                    'severity': risk_info[1],
                    'port': port,
                    'service': service,
                    'version': version,
                    'protocol': proto,
                    'description': self._generate_description(port, proto),
                    'solution': self._generate_solution(port),
                    'cpe': cpe
                })

                if self.dashboard:
                    self.dashboard.update(self.task_id, advance=1)

        if self.dashboard:
            self.dashboard.update(self.task_id, completed=True)
        return results

    @staticmethod
    def _validate_target(target: str) -> bool:
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            try:
                socket.gethostbyname(target)
                return True
            except socket.error:
                print(Fore.YELLOW + f"[WARNING] 无效的目标地址: {target}")
                return False

    def _check_privileges(self):
        if platform.system().lower() == 'windows' and self.scan_type == "syn":
            print(Fore.YELLOW + "[WARNING] Windows系统不支持SYN扫描，已自动切换为TCP Connect扫描")
            self.scan_type = "connect"
            return

        if self.scan_type == "syn":
            if os.name == 'posix' and os.geteuid() != 0:
                print(Fore.YELLOW + "[WARNING] SYN扫描需要root权限，已自动降级为TCP Connect扫描")
                self.scan_type = "connect"
            elif os.name == 'nt':
                try:
                    import ctypes
                    if not ctypes.windll.shell32.IsUserAnAdmin():
                        print(Fore.YELLOW + "[WARNING] 需要管理员权限，已自动降级为TCP Connect扫描")
                        self.scan_type = "connect"
                except:
                    print(Fore.YELLOW + "[WARNING] 权限检测失败，假设无管理员权限")
                    self.scan_type = "connect"

    @staticmethod
    def _validate_scan_type(scan_type: str) -> str:
        return scan_type if scan_type in ["syn", "connect", "udp"] else "syn"

    @staticmethod
    def _generate_description(port: int, proto: str) -> str:
        descriptions = {
            21: "FTP匿名登录可能导致未授权访问",
            22: "SSH服务暴露可能导致暴力破解",
            23: "Telnet明文传输凭据极易被窃听",
            80: "HTTP服务可能存在Web应用漏洞",
            443: "HTTPS服务需检查SSL/TLS配置",
            445: "SMB服务可能受永恒之蓝漏洞影响",
            3389: "RDP暴露可能导致远程代码执行",
            6379: "Redis未授权访问风险",
            27017: "MongoDB配置不当导致数据泄露",
            3306: "MySQL弱密码和注入漏洞风险",
            5432: "PostgreSQL配置不当风险",
            5900: "VNC未授权访问风险"
        }
        return descriptions.get(port, f"开放{proto.upper()}端口 {port}")

    @staticmethod
    def _generate_solution(port: int) -> str:
        solutions = {
            21: "1. 禁用匿名登录\n2. 使用SFTP替代",
            22: "1. 启用密钥认证\n2. 配置Fail2ban防护",
            23: "1. 立即停止Telnet服务\n2. 改用SSH协议",
            445: "1. 禁用SMBv1\n2. 安装最新安全补丁",
            3389: "1. 限制访问IP范围\n2. 启用网络级认证",
            6379: "1. 绑定指定IP\n2. 启用认证功能",
            27017: "1. 启用身份验证\n2. 配置网络隔离",
            3306: "1. 禁用root远程登录\n2. 定期更换密码",
            5432: "1. 限制访问IP\n2. 启用SSL加密",
            5900: "1. 启用强密码认证\n2. 使用SSH隧道"
        }
        return solutions.get(port, "1. 根据业务需要关闭端口\n2. 配置防火墙访问控制")

# 使用示例
if __name__ == "__main__":
    scanner = PortScanner(scan_type="syn")
    results = scanner.scan("example.com")
    for item in results:
        print(f"[{item['severity']}] {item['port']}/{item['protocol']} {item['service']}")
        print(f"描述：{item['description']}")
        print(f"解决方案：{item['solution']}\n")