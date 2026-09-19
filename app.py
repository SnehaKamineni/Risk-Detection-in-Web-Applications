from flask import Flask, render_template, request
from urllib.parse import urlparse

from nmap_scanner import run_nmap_scan
from semgrep_scanner import run_semgrep_scan

from zapv2 import ZAPv2
from dotenv import load_dotenv

import os
import time


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()

API_KEY = os.getenv("ZAP_API_KEY")


# ============================================================
# OWASP ZAP CONFIGURATION
# ============================================================

ZAP_HOST = "127.0.0.1"
ZAP_PORT = 8080

ZAP_PROXIES = {
    "http": f"http://{ZAP_HOST}:{ZAP_PORT}",
    "https": f"http://{ZAP_HOST}:{ZAP_PORT}"
}


zap = ZAPv2(
    apikey=API_KEY,
    proxies=ZAP_PROXIES
)


# ============================================================
# LATEST SCAN RESULTS
# ============================================================

latest_nmap_results = []
latest_semgrep_results = []


# ============================================================
# HOME
# ============================================================

@app.route("/", methods=["GET"])
def home():

    zap_connected = False

    try:

        version = zap.core.version

        if version:
            zap_connected = True

    except Exception:

        zap_connected = False


    return render_template(
        "index.html",
        zap_connected=zap_connected
    )


# ============================================================
# NMAP RESULTS
# ============================================================

@app.route("/nmap-results", methods=["GET"])
def nmap_results_page():

    return render_template(
        "nmap_results.html",
        nmap_results=latest_nmap_results,
        total_ports=len(latest_nmap_results)
    )


# ============================================================
# SEMGREP RESULTS
# ============================================================

@app.route("/semgrep-results", methods=["GET"])
def semgrep_results_page():

    return render_template(
        "semgrep_results.html",
        semgrep_results=latest_semgrep_results,
        total_semgrep_findings=len(latest_semgrep_results)
    )


# ============================================================
# SECURITY SCAN
# ============================================================

@app.route("/scan", methods=["POST"])
def scan():

    global latest_nmap_results
    global latest_semgrep_results


    # ========================================================
    # TARGET URL
    # ========================================================

    target_url = request.form.get(
        "url",
        ""
    ).strip()


    if not target_url:

        return render_template(
            "index.html",
            error="Please enter a target URL.",
            zap_connected=False
        )


    # ========================================================
    # URL VALIDATION
    # ========================================================

    parsed_url = urlparse(target_url)


    if not parsed_url.scheme or not parsed_url.netloc:

        return render_template(
            "index.html",
            error="Please enter a valid URL.",
            zap_connected=False
        )


    hostname = parsed_url.hostname


    if not hostname:

        return render_template(
            "index.html",
            error="Could not determine the target host.",
            zap_connected=False
        )


    print()
    print("=" * 40)
    print("TARGET INFORMATION")
    print("=" * 40)

    print("Web Target:", target_url)
    print("Nmap Target:", hostname)


    # ========================================================
    # CHECK ZAP
    # ========================================================

    try:

        zap_version = zap.core.version

    except Exception as error:

        print(
            "ZAP connection failed:",
            error
        )

        return render_template(
            "index.html",
            error=(
                "Unable to connect to OWASP ZAP. "
                "Make sure ZAP is running on port 8080."
            ),
            zap_connected=False
        )


    # ========================================================
    # OWASP ZAP SCAN
    # ========================================================

    print()
    print("=" * 40)
    print("STARTING OWASP ZAP SCAN")
    print("=" * 40)


    try:

        print("Opening target in ZAP...")

        zap.urlopen(target_url)

        time.sleep(2)


        # ----------------------------------------------------
        # SEARCH ENDPOINT
        # ----------------------------------------------------

        if hostname in (
            "127.0.0.1",
            "localhost"
        ):

            search_url = (
                target_url.rstrip("/")
                + "/search?query=test"
            )

            print(
                "Opening search endpoint in ZAP..."
            )

            try:

                zap.urlopen(search_url)

                time.sleep(1)

            except Exception as error:

                print(
                    "Could not open search endpoint:",
                    error
                )


        # ----------------------------------------------------
        # SPIDER
        # ----------------------------------------------------

        print()
        print("Starting ZAP Spider...")

        spider_scan_id = zap.spider.scan(
            target_url
        )


        while True:

            progress = int(
                zap.spider.status(
                    spider_scan_id
                )
            )

            if progress >= 100:
                break

            time.sleep(1)


        print(
            "ZAP Spider Completed."
        )


        # ----------------------------------------------------
        # ACTIVE SCAN
        # ----------------------------------------------------

        print()
        print(
            "Starting ZAP Active Scan..."
        )

        print(
            "Using Scan Policy: WebShield Policy"
        )


        active_scan_id = zap.ascan.scan(
            url=target_url,
            recurse=True,
            inscopeonly=False,
            scanpolicyname="WebShield Policy"
        )


        while True:

            progress = int(
                zap.ascan.status(
                    active_scan_id
                )
            )

            print(
                "ZAP Active Scan Progress:",
                str(progress) + "%"
            )


            if progress >= 100:
                break


            time.sleep(2)


        print(
            "ZAP Active Scan Completed."
        )


        # ----------------------------------------------------
        # ALERTS
        # ----------------------------------------------------

        alerts = zap.core.alerts(
            baseurl=target_url
        )


        print()
        print(
            "ZAP Vulnerabilities Found:",
            len(alerts)
        )


    except Exception as error:

        print(
            "ZAP scan failed:",
            error
        )

        alerts = []


    # ========================================================
    # ZAP SEVERITY
    # ========================================================

    high_count = 0
    medium_count = 0
    low_count = 0


    for alert in alerts:

        risk = str(
            alert.get(
                "risk",
                ""
            )
        ).lower()


        if risk == "high":

            high_count += 1

        elif risk == "medium":

            medium_count += 1

        elif risk == "low":

            low_count += 1


    # ========================================================
    # NMAP
    # ========================================================

    print()
    print("=" * 40)
    print("STARTING NMAP SCAN")
    print("=" * 40)

    print(
        "Nmap Target:",
        hostname
    )


    try:

        nmap_results = run_nmap_scan(
            hostname
        )

    except Exception as error:

        print(
            "Nmap scan failed:",
            error
        )

        nmap_results = []


    latest_nmap_results = nmap_results


    print()
    print("=" * 40)
    print("NMAP RESULTS")
    print("=" * 40)


    for result in nmap_results:

        print()
        print(
            "Host:",
            result.get("host")
        )

        print(
            "Port:",
            result.get("port")
        )

        print(
            "Protocol:",
            result.get("protocol")
        )

        print(
            "State:",
            result.get("state")
        )

        print(
            "Service:",
            result.get("service")
        )

        print(
            "Product:",
            result.get("product")
        )

        print(
            "Version:",
            result.get("version")
        )

        print(
            "Extra Info:",
            result.get("extra_info")
        )


    # ========================================================
    # SEMGREP
    # ========================================================

    print()
    print("=" * 40)
    print("STARTING SEMGREP SCAN")
    print("=" * 40)


    try:

        semgrep_results = run_semgrep_scan(
            "test_target.py"
        )

    except Exception as error:

        print(
            "Semgrep scan failed:",
            error
        )

        semgrep_results = []


    latest_semgrep_results = semgrep_results


    print()
    print("=" * 40)
    print("SEMGREP RESULTS")
    print("=" * 40)

    print(
        "Semgrep Findings:",
        len(semgrep_results)
    )


    for finding in semgrep_results:

        print()

        print(
            "Rule:",
            finding.get("check_id")
        )

        print(
            "File:",
            finding.get("path")
        )

        print(
            "Line:",
            finding.get("start_line")
        )

        print(
            "Severity:",
            finding.get("severity")
        )

        print(
            "Message:",
            finding.get("message")
        )


    # ========================================================
    # SECURITY REPORT
    # ========================================================

    return render_template(

        "scan_result.html",

        url=target_url,

        alerts=alerts,

        total_alerts=len(alerts),

        high_count=high_count,

        medium_count=medium_count,

        low_count=low_count,

        zap_version=zap_version,

        nmap_results=nmap_results,

        total_ports=len(nmap_results),

        semgrep_results=semgrep_results,

        total_semgrep_findings=len(
            semgrep_results
        )

    )


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )