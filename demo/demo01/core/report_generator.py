import os
import pdfkit
import html
from datetime import datetime
from collections import defaultdict
from jinja2 import Environment, FileSystemLoader, select_autoescape
from typing import List, Dict

class ReportGenerator:
    @staticmethod
    def generate(data: dict, format: str = 'html', output_dir: str = ".") -> None:
        """生成安全扫描报告（HTML 和 PDF）"""
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)
        # 丰富报告数据
        enriched_data = ReportGenerator.enrich_data(data)
        # 初始化模板环境并启用自动转义，且添加自定义过滤器
        env = Environment(
            loader=FileSystemLoader('templates'),
            autoescape=select_autoescape(['html', 'xml'])
        )
        env.filters['escape_html'] = ReportGenerator.escape_html_filter
        # 渲染HTML模板
        template = env.get_template('report_template.html')
        html_content = template.render(report=enriched_data)
        # 保存HTML报告文件
        html_path = os.path.join(output_dir, 'report.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        # 生成PDF报告（如果需要）
        if format in ('pdf', 'both'):
            try:
                pdf_path = os.path.join(output_dir, 'report.pdf')
                pdfkit.from_file(html_path, pdf_path, options={
                    'enable-local-file-access': '',
                    'encoding': 'UTF-8',
                    'quiet': '',
                    'margin-top': '15mm',
                    'margin-right': '10mm',
                    'margin-bottom': '15mm',
                    'margin-left': '10mm',
                    'footer-center': '[page]/[topage]'
                })
            except Exception as e:
                print(f"PDF生成失败：{str(e)}")
                print("提示：请确保wkhtmltopdf已正确安装并配置到PATH")

    @staticmethod
    def enrich_data(raw_data: dict) -> dict:
        """整合并增强扫描结果数据，用于报告展示"""
        processed = raw_data.copy()
        processed.setdefault('report_date', datetime.now().strftime("%Y-%m-%d %H:%M"))
        processed.setdefault('metrics', {})
        # 统一各漏洞数据格式
        for vuln in processed.get('vulns', []):
            # 统一严重等级表示（映射中文等级为critical/high/medium/low）
            severity_map = {'严重': 'critical', '高危': 'high', '中危': 'medium', '低危': 'low'}
            if 'severity' in vuln:
                sev = str(vuln['severity'])
                vuln['severity'] = severity_map.get(sev, sev.lower())
            else:
                vuln['severity'] = 'low'
            # 统一修复建议字段为列表
            if 'solution' in vuln:
                sol = vuln.pop('solution')
                vuln['solutions'] = [sol] if isinstance(sol, str) else sol
            vuln.setdefault('description', '暂无详情')
            vuln.setdefault('solutions', ['请参考上述风险描述采取修复措施'])
            vuln.setdefault('references', [])
            # 如果有 payload、url 或其他字段需要展示，也可以在这里进行转义处理（模板自动转义也能保护大部分内容）
        # 统计漏洞类型数量分布
        type_stats = defaultdict(int)
        for vuln in processed.get('vulns', []):
            type_stats[vuln['type']] += 1
        processed['vuln_types'] = sorted(
            [{'type': k, 'count': v} for k, v in type_stats.items()],
            key=lambda x: x['count'],
            reverse=True
        )
        # 统计漏洞严重等级分布
        severity_stats = defaultdict(int)
        for vuln in processed.get('vulns', []):
            severity_stats[vuln['severity']] += 1
        processed['severity_stats'] = {
            'critical': severity_stats.get('critical', 0),
            'high': severity_stats.get('high', 0),
            'medium': severity_stats.get('medium', 0),
            'low': severity_stats.get('low', 0)
        }
        # 综合计算整体风险等级
        processed['risk_level'] = ReportGenerator.calculate_risk_level(processed.get('vulns', []))
        # 对部分文本字段（如 description、solutions）进行转义（模板自动转义已保护其他变量）
        for vuln in processed.get('vulns', []):
            vuln['description'] = ReportGenerator.escape_html(vuln['description'])
            vuln['solutions'] = [ReportGenerator.escape_html(s) for s in vuln['solutions']]
        # 增强指标的默认值
        processed['metrics'].setdefault('duration', '0.00秒')
        processed['metrics'].setdefault('success_rate', '100%')
        processed['metrics'].setdefault('scanned_items', len(processed.get('vulns', [])))
        return processed

    @staticmethod
    def calculate_risk_level(vulns: List[Dict]) -> str:
        """根据所有漏洞的严重性动态计算整体风险等级"""
        weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        total_score = 0
        has_critical = False
        has_high = False
        has_medium = False
        has_low = False
        for v in vulns:
            sev = str(v.get('severity', '')).lower()
            total_score += weights.get(sev, 0)
            if sev == 'critical':
                has_critical = True
            elif sev == 'high':
                has_high = True
            elif sev == 'medium':
                has_medium = True
            elif sev == 'low':
                has_low = True
        if total_score == 0:
            return '无风险'
        if has_critical:
            return '严重风险'
        if has_high:
            return '严重风险' if total_score >= 15 else '高危'
        if has_medium:
            return '高危' if total_score >= 10 else '中危'
        return '中危' if total_score >= 10 else '低危'

    @staticmethod
    def escape_html(text: str) -> str:
        """对文本进行HTML转义"""
        return html.escape(text) if text else ''

    @staticmethod
    def escape_html_filter(text: str) -> str:
        """作为Jinja2过滤器的HTML转义函数"""
        return ReportGenerator.escape_html(text)
