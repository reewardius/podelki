import re
import sys
import os
from collections import defaultdict
from datetime import datetime

def parse_vulnerabilities(text):
    # Регулярное выражение для извлечения основных данных
    pattern = r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*?)(?=$)'
    
    vulns = []
    
    for match in re.finditer(pattern, text, re.MULTILINE):
        cve_or_type, protocol, severity, remaining_text = match.groups()
        
        # Извлекаем URL и дополнительные данные
        url = remaining_text.strip()
        extractors = []
        
        # Ищем квадратные скобки в конце (extractors)
        brackets_match = re.search(r'(.*?)(\s+\[.*?\]\s*)$', url)
        if brackets_match:
            url = brackets_match.group(1).strip()
            # Извлекаем все данные в квадратных скобках
            extractor_text = brackets_match.group(2).strip()
            # Используем отдельное регулярное выражение для выделения текста в квадратных скобках
            extractor_matches = re.findall(r'\[(.*?)\]', extractor_text)
            for ext in extractor_matches:
                extractors.append(ext)
        
        vulns.append({
            "cve_or_type": cve_or_type.strip(),
            "protocol": protocol.strip(),
            "severity": severity.strip(),
            "url": url,
            "extractors": extractors
        })
    
    return vulns

def generate_html_report(vulnerabilities, input_filename):
    # Группировка уязвимостей по критичности
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    vuln_by_severity = defaultdict(list)
    
    for vuln in vulnerabilities:
        severity = vuln["severity"].lower()
        vuln_by_severity[severity].append(vuln)
    
    # HTML шаблон
    report_title = os.path.splitext(os.path.basename(input_filename))[0]
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет по уязвимостям: {report_title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            margin-top: 30px;
            padding: 8px 15px;
            border-radius: 4px;
            color: white;
        }}
        .critical h2 {{ background-color: #e74c3c; }}
        .high h2 {{ background-color: #e67e22; }}
        .medium h2 {{ background-color: #f39c12; }}
        .low h2 {{ background-color: #2ecc71; }}
        .info h2 {{ background-color: #3498db; }}
        .unknown h2 {{ background-color: #95a5a6; }}
        
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }}
        .vuln-table th, .vuln-table td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }}
        .vuln-table th {{
            background-color: #f2f2f2;
        }}
        .vuln-table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .vuln-url {{
            word-break: break-all;
        }}
        .extractor {{
            display: inline-block;
            background-color: #f1f1f1;
            padding: 2px 5px;
            margin: 2px;
            border-radius: 3px;
            font-size: 0.85em;
            font-family: monospace;
            border: 1px solid #ddd;
        }}
        .extractors-cell {{
            max-width: 300px;
        }}
        .summary {{
            margin-bottom: 20px;
            padding: 15px;
            background-color: #edf2f7;
            border-radius: 4px;
        }}
        .summary-table {{
            width: 300px;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        .summary-table td {{
            padding: 5px 10px;
            border: 1px solid #ddd;
        }}
        .summary-table td:first-child {{
            font-weight: bold;
        }}
        footer {{
            margin-top: 30px;
            text-align: center;
            font-size: 0.8em;
            color: #7f8c8d;
        }}
        .source-file {{
            font-style: italic;
            color: #7f8c8d;
            margin-bottom: 20px;
        }}
        .no-vulns {{
            padding: 15px;
            background-color: #f8d7da;
            color: #721c24;
            border-radius: 4px;
            margin: 20px 0;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 3px 6px;
            border-radius: 3px;
            color: white;
            font-size: 0.8em;
            margin-right: 5px;
        }}
        .badge-critical {{ background-color: #e74c3c; }}
        .badge-high {{ background-color: #e67e22; }}
        .badge-medium {{ background-color: #f39c12; }}
        .badge-low {{ background-color: #2ecc71; }}
        .badge-info {{ background-color: #3498db; }}
        .badge-unknown {{ background-color: #95a5a6; }}
        .tooltip {{
            position: relative;
            display: inline-block;
            cursor: help;
        }}
        .tooltip .tooltiptext {{
            visibility: hidden;
            width: 200px;
            background-color: #555;
            color: #fff;
            text-align: center;
            border-radius: 6px;
            padding: 5px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
        }}
        .tooltip:hover .tooltiptext {{
            visibility: visible;
            opacity: 1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Отчет по уязвимостям</h1>
        <div class="source-file">Исходный файл: {input_filename}</div>
        
        <div class="summary">
            <h3>Сводная информация</h3>
            <table class="summary-table">
                <tr>
                    <td>Critical</td>
                    <td>{len(vuln_by_severity.get("critical", []))}</td>
                </tr>
                <tr>
                    <td>High</td>
                    <td>{len(vuln_by_severity.get("high", []))}</td>
                </tr>
                <tr>
                    <td>Medium</td>
                    <td>{len(vuln_by_severity.get("medium", []))}</td>
                </tr>
                <tr>
                    <td>Low</td>
                    <td>{len(vuln_by_severity.get("low", []))}</td>
                </tr>
                <tr>
                    <td>Info</td>
                    <td>{len(vuln_by_severity.get("info", []))}</td>
                </tr>
                <tr>
                    <td>Unknown</td>
                    <td>{len(vuln_by_severity.get("unknown", []))}</td>
                </tr>
                <tr>
                    <td>Всего</td>
                    <td>{len(vulnerabilities)}</td>
                </tr>
            </table>
        </div>
"""

    if not vulnerabilities:
        html += """
        <div class="no-vulns">
            <p>В отчете не найдено уязвимостей. Проверьте формат входного файла.</p>
        </div>
        """
    else:
        # Добавляем секции по уровням критичности в нужном порядке
        for severity_name in sorted(vuln_by_severity.keys(), key=lambda x: severity_order.get(x, 999)):
            vulns = vuln_by_severity[severity_name]
            if not vulns:
                continue
                
            severity_display = severity_name.upper()
            html += f"""
            <div class="{severity_name}">
                <h2>{severity_display} ({len(vulns)})</h2>
                <table class="vuln-table">
                    <thead>
                        <tr>
                            <th>CVE/Тип</th>
                            <th>Протокол</th>
                            <th>URL</th>
                            <th>Дополнительная информация</th>
                        </tr>
                    </thead>
                    <tbody>
    """

            for vuln in vulns:
                # Формируем ячейку с extractors, если они есть
                extractors_html = ""
                if vuln["extractors"]:
                    extractors_html = '<div class="extractors-cell">'
                    for extractor in vuln["extractors"]:
                        extractors_html += f'<span class="extractor">{extractor}</span> '
                    extractors_html += '</div>'
                
                html += f"""
                        <tr>
                            <td>{vuln["cve_or_type"]}</td>
                            <td>{vuln["protocol"]}</td>
                            <td class="vuln-url"><a href="{vuln["url"]}" target="_blank">{vuln["url"]}</a></td>
                            <td>{extractors_html}</td>
                        </tr>
    """

            html += """
                    </tbody>
                </table>
            </div>
    """

    # Завершаем HTML
    current_date = datetime.now().strftime("%d.%m.%Y %H:%M")
    html += f"""
        <footer>
            Отчет сгенерирован: {current_date}
        </footer>
    </div>
</body>
</html>
"""
    return html

def main():
    # Проверяем, что файл указан в аргументах
    if len(sys.argv) != 2:
        print("Использование: python script.py путь_к_файлу.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # Проверяем существование файла
    if not os.path.exists(input_file):
        print(f"Ошибка: Файл '{input_file}' не найден.")
        sys.exit(1)
    
    try:
        # Читаем содержимое файла
        with open(input_file, 'r', encoding='utf-8') as f:
            text = f.read()
        
        vulnerabilities = parse_vulnerabilities(text)
        html_report = generate_html_report(vulnerabilities, input_file)
        
        # Формируем имя выходного файла
        output_file = os.path.splitext(input_file)[0] + "_report.html"
        
        # Сохраняем HTML отчет
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        print(f"Отчет успешно сгенерирован и сохранен в файл: {output_file}")
        print(f"Всего обработано уязвимостей: {len(vulnerabilities)}")
        
    except Exception as e:
        print(f"Ошибка при обработке файла: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()