"""Reports - JSON, HTML, CSV, XML, PDF export, scan comparison."""

import csv
import io
import json
import os
import time
from datetime import datetime


def _ensure_output_dir(directory="reports"):
    """Create output directory if it doesn't exist."""
    os.makedirs(directory, exist_ok=True)
    return directory


def json_export(scan_data, filename=None, output_dir="reports"):
    """Export scan results to JSON."""
    result = {"success": False}

    try:
        _ensure_output_dir(output_dir)

        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shockwave_report_{ts}.json"

        filepath = os.path.join(output_dir, filename)

        export_data = {
            "shockwave_report": {
                "version": "1.0",
                "generated_at": datetime.now().isoformat(),
                "tool": "Shockwave Network Diagnostic Toolkit",
                "data": scan_data,
            }
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, default=str, ensure_ascii=False)

        result.update({
            "success": True,
            "filepath": os.path.abspath(filepath),
            "filename": filename,
            "size_bytes": os.path.getsize(filepath),
        })

    except (OSError, TypeError) as e:
        result["error"] = str(e)

    return result


def html_report(scan_data, filename=None, output_dir="reports", title="Shockwave Report"):
    """Generate HTML report from scan results."""
    result = {"success": False}

    try:
        _ensure_output_dir(output_dir)

        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shockwave_report_{ts}.html"

        filepath = os.path.join(output_dir, filename)

        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0d0d0d 0%, #1a0a2e 50%, #0d0d0d 100%);
            color: #e0d0ff;
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, #1a0a2e, #2d1b69);
            border: 1px solid #6b3fa0;
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            font-size: 2.5em;
            background: linear-gradient(135deg, #9b59b6, #e74c9b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}
        .header .meta {{ color: #9b8ec4; font-size: 0.9em; }}
        .section {{
            background: rgba(26, 10, 46, 0.8);
            border: 1px solid #3d2066;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .section-title {{
            background: linear-gradient(135deg, #2d1b69, #4a2d8a);
            padding: 15px 20px;
            font-size: 1.2em;
            color: #d4a5ff;
            border-bottom: 1px solid #3d2066;
        }}
        .section-body {{ padding: 20px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            background: #2d1b69;
            color: #d4a5ff;
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 10px 15px;
            border-bottom: 1px solid #2d1b69;
            color: #c0b0e0;
        }}
        tr:hover {{ background: rgba(107, 63, 160, 0.15); }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
        }}
        .badge-success {{ background: #2d1b69; color: #b266ff; }}
        .badge-danger {{ background: #4a1030; color: #ff6b9d; }}
        .badge-warning {{ background: #4a3500; color: #ffb366; }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #6b5b8a;
            font-size: 0.85em;
            margin-top: 30px;
        }}
        pre {{
            background: #0d0a1a;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            color: #b0a0d0;
            font-size: 0.9em;
            border: 1px solid #2d1b69;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SHOCKWAVE</h1>
            <div class="meta">
                Network Diagnostic Report<br>
                Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>
"""

        if isinstance(scan_data, dict):
            for section_name, section_data in scan_data.items():
                html += f'        <div class="section">\n'
                html += f'            <div class="section-title">{section_name}</div>\n'
                html += f'            <div class="section-body">\n'

                if isinstance(section_data, dict):
                    html += '                <table>\n'
                    html += '                    <tr><th>Property</th><th>Value</th></tr>\n'
                    for k, v in section_data.items():
                        val_str = str(v)
                        if isinstance(v, bool):
                            badge_cls = "badge-success" if v else "badge-danger"
                            val_str = f'<span class="badge {badge_cls}">{"Yes" if v else "No"}</span>'
                        html += f'                    <tr><td>{k}</td><td>{val_str}</td></tr>\n'
                    html += '                </table>\n'
                elif isinstance(section_data, list):
                    if section_data and isinstance(section_data[0], dict):
                        keys = list(section_data[0].keys())
                        html += '                <table>\n'
                        html += '                    <tr>' + ''.join(f'<th>{k}</th>' for k in keys) + '</tr>\n'
                        for item in section_data:
                            html += '                    <tr>' + ''.join(f'<td>{item.get(k, "")}</td>' for k in keys) + '</tr>\n'
                        html += '                </table>\n'
                    else:
                        html += f'                <pre>{json.dumps(section_data, indent=2, default=str)}</pre>\n'
                else:
                    html += f'                <pre>{section_data}</pre>\n'

                html += '            </div>\n'
                html += '        </div>\n'
        else:
            html += f'        <div class="section"><div class="section-body"><pre>{json.dumps(scan_data, indent=2, default=str)}</pre></div></div>\n'

        html += f"""
        <div class="footer">
            Shockwave Network Diagnostic Toolkit &bull; {datetime.now().year}
        </div>
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        result.update({
            "success": True,
            "filepath": os.path.abspath(filepath),
            "filename": filename,
            "size_bytes": os.path.getsize(filepath),
        })

    except (OSError, TypeError) as e:
        result["error"] = str(e)

    return result


def csv_export(scan_data, filename=None, output_dir="reports"):
    """Export scan results to CSV."""
    result = {"success": False}

    try:
        _ensure_output_dir(output_dir)

        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shockwave_report_{ts}.csv"

        filepath = os.path.join(output_dir, filename)

        rows = []
        if isinstance(scan_data, dict):
            for section, data in scan_data.items():
                if isinstance(data, dict):
                    for k, v in data.items():
                        rows.append({"section": section, "key": k, "value": str(v)})
                elif isinstance(data, list):
                    for i, item in enumerate(data):
                        if isinstance(item, dict):
                            for k, v in item.items():
                                rows.append({"section": section, "index": i, "key": k, "value": str(v)})
                        else:
                            rows.append({"section": section, "index": i, "value": str(item)})
                else:
                    rows.append({"section": section, "value": str(data)})

        if rows:
            fieldnames = list(rows[0].keys())
            for row in rows[1:]:
                for k in row:
                    if k not in fieldnames:
                        fieldnames.append(k)

            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
        else:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("No data to export\n")

        result.update({
            "success": True,
            "filepath": os.path.abspath(filepath),
            "filename": filename,
            "rows": len(rows),
            "size_bytes": os.path.getsize(filepath),
        })

    except (OSError, TypeError) as e:
        result["error"] = str(e)

    return result


def xml_export(scan_data, filename=None, output_dir="reports"):
    """Export scan results to XML."""
    result = {"success": False}

    try:
        _ensure_output_dir(output_dir)

        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shockwave_report_{ts}.xml"

        filepath = os.path.join(output_dir, filename)

        xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml += '<shockwave_report>\n'
        xml += f'  <metadata>\n'
        xml += f'    <tool>Shockwave Network Diagnostic Toolkit</tool>\n'
        xml += f'    <version>1.0</version>\n'
        xml += f'    <generated>{datetime.now().isoformat()}</generated>\n'
        xml += f'  </metadata>\n'
        xml += f'  <results>\n'

        xml += _dict_to_xml(scan_data, indent=4)

        xml += f'  </results>\n'
        xml += '</shockwave_report>\n'

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(xml)

        result.update({
            "success": True,
            "filepath": os.path.abspath(filepath),
            "filename": filename,
            "size_bytes": os.path.getsize(filepath),
        })

    except (OSError, TypeError) as e:
        result["error"] = str(e)

    return result


def _dict_to_xml(data, indent=0, tag=None):
    """Convert dict/list to XML string."""
    prefix = " " * indent
    xml = ""

    if isinstance(data, dict):
        for key, value in data.items():
            safe_key = _xml_safe_tag(str(key))
            if isinstance(value, (dict, list)):
                xml += f"{prefix}<{safe_key}>\n"
                xml += _dict_to_xml(value, indent + 2)
                xml += f"{prefix}</{safe_key}>\n"
            else:
                xml += f"{prefix}<{safe_key}>{_xml_escape(str(value))}</{safe_key}>\n"
    elif isinstance(data, list):
        for i, item in enumerate(data):
            xml += f"{prefix}<item index=\"{i}\">\n"
            xml += _dict_to_xml(item, indent + 2)
            xml += f"{prefix}</item>\n"
    else:
        xml += f"{prefix}{_xml_escape(str(data))}\n"

    return xml


def _xml_safe_tag(tag):
    """Make a string safe for XML tag names."""
    import re
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", tag)
    if safe and safe[0].isdigit():
        safe = "_" + safe
    return safe or "item"


def _xml_escape(s):
    """Escape special characters for XML."""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&apos;"))


def pdf_report(scan_data, filename=None, output_dir="reports", title="Shockwave Report"):
    """Generate PDF report (via HTML conversion or text-based)."""
    result = {"success": False}

    try:
        _ensure_output_dir(output_dir)

        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shockwave_report_{ts}.pdf"

        filepath = os.path.join(output_dir, filename)

        html_result = html_report(scan_data, filename="__temp_pdf.html",
                                   output_dir=output_dir, title=title)

        if html_result["success"]:
            html_path = html_result["filepath"]

            try:
                import subprocess
                proc = subprocess.run(
                    ["wkhtmltopdf", "--quiet", "--page-size", "A4",
                     "--margin-top", "10mm", "--margin-bottom", "10mm",
                     html_path, filepath],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=30)

                if proc.returncode == 0 and os.path.exists(filepath):
                    os.remove(html_path)
                    result.update({
                        "success": True,
                        "filepath": os.path.abspath(filepath),
                        "filename": filename,
                        "size_bytes": os.path.getsize(filepath),
                        "method": "wkhtmltopdf",
                    })
                    return result
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            try:
                import subprocess
                proc = subprocess.run(
                    ["weasyprint", html_path, filepath],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=30)

                if proc.returncode == 0 and os.path.exists(filepath):
                    os.remove(html_path)
                    result.update({
                        "success": True,
                        "filepath": os.path.abspath(filepath),
                        "filename": filename,
                        "size_bytes": os.path.getsize(filepath),
                        "method": "weasyprint",
                    })
                    return result
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            os.rename(html_path, filepath.replace(".pdf", ".html"))
            result.update({
                "success": True,
                "filepath": os.path.abspath(filepath.replace(".pdf", ".html")),
                "filename": filename.replace(".pdf", ".html"),
                "note": "PDF converters not available, exported as HTML instead. Install wkhtmltopdf or weasyprint for PDF support.",
                "method": "html_fallback",
            })
        else:
            result["error"] = "Failed to generate intermediate HTML"

    except (OSError, TypeError) as e:
        result["error"] = str(e)

    return result


def scan_comparison(scan1, scan2, label1="Scan 1", label2="Scan 2"):
    """Compare two scan results and highlight differences."""
    result = {"success": False, "label1": label1, "label2": label2, "differences": [], "summary": {}}

    try:
        added = []
        removed = []
        changed = []

        if isinstance(scan1, dict) and isinstance(scan2, dict):
            all_keys = set(list(scan1.keys()) + list(scan2.keys()))

            for key in sorted(all_keys):
                if key not in scan1:
                    added.append({"key": key, "value": scan2[key]})
                elif key not in scan2:
                    removed.append({"key": key, "value": scan1[key]})
                elif str(scan1[key]) != str(scan2[key]):
                    changed.append({
                        "key": key,
                        "old_value": scan1[key],
                        "new_value": scan2[key],
                    })

        result.update({
            "success": True,
            "added": added,
            "removed": removed,
            "changed": changed,
            "summary": {
                "total_added": len(added),
                "total_removed": len(removed),
                "total_changed": len(changed),
                "identical": len(added) == 0 and len(removed) == 0 and len(changed) == 0,
            },
        })

    except Exception as e:
        result["error"] = str(e)

    return result
