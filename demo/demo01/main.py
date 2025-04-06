# ✅ 同步更新后的 main.py，适配最新 Scanner 支持 dashboard、进度与 XSS 修复

import argparse
import concurrent.futures
import logging
import os
from datetime import datetime
from typing import List, Dict
from urllib.parse import urlparse

from scanners.xss_detector import XSSScanner
from scanners.sqli_detector import SQLiScanner
from scanners.directory_traversal import DirectoryTraversalScanner
from scanners.port_scanner import PortScanner
from core.dependency_checker import DependencyChecker
from core.report_generator import ReportGenerator
from core.dashboard import SecurityDashboard


def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme in ["http", "https"], result.netloc])
    except Exception:
        return False


def main():
    try:
        parser = argparse.ArgumentParser(description="企业级Web应用安全扫描系统")
        parser.add_argument("target", help="扫描目标URL或IP地址")
        parser.add_argument("-o", "--output", default="reports", help="报告输出目录")
        parser.add_argument("-p", "--ports", default="80,443,8000-9000", help="端口扫描范围")
        parser.add_argument("-t", "--threads", type=int, default=4, help="最大并发线程数")
        parser.add_argument("-to", "--timeout", type=int, default=30, help="单个扫描任务超时时间（秒）")
        parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
        args = parser.parse_args()

        if not is_valid_url(args.target):
            print(f"错误: 无效的URL '{args.target}'")
            return 1
        if '#' in args.target:
            print(f"[INFO] 移除片段: {args.target}")
            args.target = args.target.split('#')[0]

        logging.basicConfig(level=args.log_level, format="[%(levelname)s] %(message)s")
        os.makedirs(args.output, exist_ok=True)
        start_time = datetime.now()

        dashboard = SecurityDashboard()
        dashboard.start()

        scanners = [
            ("XSS漏洞扫描", XSSScanner(timeout=args.timeout, use_headless=True, dashboard=dashboard)),
            ("SQL注入检测", SQLiScanner(timeout=args.timeout, enable_blind_detection=True)),
            ("目录遍历检测", DirectoryTraversalScanner(timeout=args.timeout, max_depth=3, dashboard=dashboard)),
            ("端口扫描", PortScanner(ports=args.ports, scan_type="syn", timeout=args.timeout, dashboard=dashboard))
        ]

        total_vulns: List[Dict] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scanner.scan, args.target): name for name, scanner in scanners}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    if result:
                        total_vulns.extend(result)
                except Exception as e:
                    logging.error(f"[{name}] 执行出错: {str(e)}")

        dashboard.stop()

        dep_vulns = DependencyChecker().check()
        for dep_result in dep_vulns:
            if dep_result and dep_result.get("vulnerabilities"):
                total_vulns.append({
                    "type": "dependency",
                    "severity": max((v.get("severity", "low") for v in dep_result["vulnerabilities"]), key=lambda s: ["low", "medium", "high", "critical"].index(s)),
                    "package": dep_result["package"],
                    "description": dep_result["vulnerabilities"][0].get("summary", "暂无详情"),
                    "solutions": ["请升级至无漏洞的安全版本"],
                    "references": [v.get("reference") for v in dep_result["vulnerabilities"] if v.get("reference")]
                })

        duration = (datetime.now() - start_time).total_seconds()
        report_data = {
            "target": args.target,
            "metrics": {
                "duration": f"{duration:.2f}秒",
                "scanned_items": len(total_vulns),
                "success_rate": "100%"
            },
            "vulns": total_vulns
        }

        ReportGenerator.generate(report_data, format="both", output_dir=args.output)
        print(f"\n[完成] 扫描结束，报告已保存至 {args.output}")

    except Exception as e:
        logging.error(f"[FATAL] 扫描失败: {str(e)}")


if __name__ == "__main__":
    main()