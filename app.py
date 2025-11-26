from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
)
from scanner.scanner_core import scan as run_scan
from scanner import db

import pandas as pd
import os


app = Flask(__name__)
app.secret_key = "change_this_in_production"

# Initialize database once at startup
db.init_db()


@app.route("/")
def index():
    scans = db.get_scans()
    return render_template("index.html", scans=scans)


@app.route("/scan", methods=["POST"])
def start_scan():
    target_url = request.form.get("target_url")
    if not target_url:
        flash("Please enter a target URL", "error")
        return redirect(url_for("index"))

    scan_id = db.create_scan(target_url)

    try:
        run_scan(target_url, scan_id)
    except Exception as e:
        db.finish_scan(scan_id, status="error")
        flash(f"Scan failed: {e}", "error")
        return redirect(url_for("index"))

    flash("Scan completed", "success")
    return redirect(url_for("view_scan", scan_id=scan_id))


@app.route("/scan/<int:scan_id>")
def view_scan(scan_id):
    scan, findings = db.get_scan_with_findings(scan_id)
    if not scan:
        flash("Scan not found", "error")
        return redirect(url_for("index"))
    return render_template("scan_detail.html", scan=scan, findings=findings)


@app.route("/scan/<int:scan_id>/report/csv")
def download_csv(scan_id):
    scan, findings = db.get_scan_with_findings(scan_id)

    if not scan:
        flash("Scan not found.", "error")
        return redirect(url_for("index"))

    if not findings:
        flash("No findings to export.", "error")
        return redirect(url_for("view_scan", scan_id=scan_id))

    rows = []
    for f in findings:
        rows.append({
            "Scan ID": scan_id,
            "Target": scan["target_url"],
            "Vulnerability": f["vuln_type"],
            "Severity": f["severity"],
            "URL": f["url"],
            "Parameter": f["parameter"] or "-",
            "Payload": f["payload"] or "-",
            "Evidence": f["evidence"] or "-",
        })

    df = pd.DataFrame(rows)

    # ✅ Create reports directory
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    # ✅ Save pretty text report
    txt_path = os.path.join(reports_dir, f"scan_{scan_id}_report.txt")
    with open(txt_path, "w", encoding="utf-8") as t:
        t.write(df.to_string(index=False))

    # ✅ Save CSV
    csv_path = os.path.join(reports_dir, f"scan_{scan_id}_report.csv")
    df.to_csv(csv_path, index=False, encoding="utf-8")

    # ✅ Send CSV file to browser
    return send_file(
        csv_path,
        as_attachment=True,
        download_name=f"scan_{scan_id}_report.csv",
        mimetype="text/csv",
    )


if __name__ == "__main__":
    app.run(debug=True)
