from flask import Flask, render_template, request
from urllib.parse import urlparse
from nmap_scanner import run_nmap_scan
from zapv2 import ZAPv2
from dotenv import load_dotenv
import os
import time

app = Flask(__name__)


# =========================================================
# OWASP ZAP CONFIGURATION
# =========================================================
load_dotenv()

API_KEY = os.getenv("ZAP_API_KEY")

proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080"
}

zap = ZAPv2(
    apikey=API_KEY,
    proxies=proxies
)


# =========================================================
# CHECK WHETHER ZAP IS CONNECTED
# =========================================================

def check_zap_connection():

    try:
        zap.core.version
        return True

    except Exception:
        return False


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    zap_connected = check_zap_connection()

    return render_template(
        "index.html",
        zap_connected=zap_connected
    )


# =========================================================
# SECURITY SCAN
# =========================================================

@app.route("/scan", methods=["POST"])
def scan():

    url = request.form.get(
        "url",
        ""
    ).strip()


    # -----------------------------------------------------
    # VALIDATE EMPTY URL
    # -----------------------------------------------------

    if not url:

        return render_template(
            "index.html",
            error="Please enter a website URL.",
            zap_connected=check_zap_connection()
        )


    # -----------------------------------------------------
    # VALIDATE URL FORMAT
    # -----------------------------------------------------

    if not url.startswith(
        ("http://", "https://")
    ):

        return render_template(
            "index.html",
            error=(
                "Please enter a complete URL starting "
                "with http:// or https://"
            ),
            zap_connected=check_zap_connection()
        )


    # -----------------------------------------------------
    # EXTRACT HOST FOR NMAP
    # -----------------------------------------------------

    parsed_url = urlparse(url)

    nmap_target = parsed_url.hostname


    if not nmap_target:

        return render_template(
            "index.html",
            error="Could not identify the target host.",
            zap_connected=check_zap_connection()
        )


    print()
    print("========================================")
    print("TARGET INFORMATION")
    print("========================================")

    print(
        "Web Target:",
        url
    )

    print(
        "Nmap Target:",
        nmap_target
    )


    # -----------------------------------------------------
    # CHECK ZAP CONNECTION
    # -----------------------------------------------------

    if not check_zap_connection():

        return render_template(
            "index.html",
            error=(
                "OWASP ZAP is not connected. "
                "Please start ZAP and try again."
            ),
            zap_connected=False
        )


    try:

        # =================================================
        # STEP 1: OWASP ZAP
        # =================================================

        print()
        print("========================================")
        print("STARTING OWASP ZAP SCAN")
        print("========================================")


        # -------------------------------------------------
        # OPEN TARGET
        # -------------------------------------------------

        print(
            "Opening target in ZAP..."
        )

        zap.urlopen(url)

        time.sleep(2)


        # -------------------------------------------------
        # OPEN SEARCH ENDPOINT
        #
        # This is only used for our local WebShield
        # test application.
        # -------------------------------------------------

        if nmap_target in (
            "127.0.0.1",
            "localhost"
        ):

            search_url = (
                url.rstrip("/")
                + "/search?query=test"
            )

            print(
                "Opening search endpoint in ZAP..."
            )

            zap.urlopen(
                search_url
            )

            time.sleep(2)


        # =================================================
        # STEP 2: ZAP SPIDER
        # =================================================

        print()
        print(
            "Starting ZAP Spider..."
        )

        spider_id = zap.spider.scan(
            url
        )


        while int(
            zap.spider.status(spider_id)
        ) < 100:

            spider_status = (
                zap.spider.status(
                    spider_id
                )
            )

            print(
                "ZAP Spider Progress:",
                spider_status + "%"
            )

            time.sleep(2)


        print(
            "ZAP Spider Completed."
        )


        # =================================================
        # STEP 3: ZAP ACTIVE SCAN
        # =================================================

        print()
        print(
            "Starting ZAP Active Scan..."
        )

        print(
            "Using Scan Policy: WebShield Policy"
        )


        active_scan_id = zap.ascan.scan(
            url,
            scanpolicyname="WebShield Policy"
        )


        while int(
            zap.ascan.status(
                active_scan_id
            )
        ) < 100:

            active_status = (
                zap.ascan.status(
                    active_scan_id
                )
            )

            print(
                "ZAP Active Scan Progress:",
                active_status + "%"
            )

            time.sleep(2)


        print(
            "ZAP Active Scan Completed."
        )


        # =================================================
        # STEP 4: GET ZAP ALERTS
        # =================================================

        alerts = zap.core.alerts(
            baseurl=url
        )


        print()
        print(
            "ZAP Vulnerabilities Found:",
            len(alerts)
        )


        # =================================================
        # STEP 5: COUNT ZAP RISK LEVELS
        # =================================================

        high_count = 0
        medium_count = 0
        low_count = 0
        info_count = 0


        for alert in alerts:

            risk = alert.get(
                "risk",
                ""
            ).lower()


            if risk == "high":

                high_count += 1


            elif risk == "medium":

                medium_count += 1


            elif risk == "low":

                low_count += 1


            else:

                info_count += 1


        # =================================================
        # STEP 6: NMAP SCAN
        # =================================================

        print()
        print("========================================")
        print("STARTING NMAP SCAN")
        print("========================================")

        print(
            "Nmap Target:",
            nmap_target
        )


        nmap_results = run_nmap_scan(
            nmap_target
        )


        # =================================================
        # STEP 7: PRINT NMAP RESULTS
        # =================================================

        print()
        print("========================================")
        print("NMAP RESULTS")
        print("========================================")


        if not nmap_results:

            print(
                "No Nmap results found."
            )


        else:

            for result in nmap_results:

                print()

                print(
                    "Host:",
                    result["host"]
                )

                print(
                    "Port:",
                    result["port"]
                )

                print(
                    "Protocol:",
                    result["protocol"]
                )

                print(
                    "State:",
                    result["state"]
                )

                print(
                    "Service:",
                    result["service"]
                )

                print(
                    "Product:",
                    result["product"]
                )

                print(
                    "Version:",
                    result["version"]
                )

                print(
                    "Extra Info:",
                    result["extra_info"]
                )


        # =================================================
        # STEP 8: DISPLAY WEB RESULTS
        # =================================================
        #
        # Nmap is currently printed only in terminal.
        # We will display it in scan_result.html after
        # confirming this backend integration works.
        # =================================================

        return render_template(
    "scan_result.html",

    url=url,

    zap_version=zap.core.version,

    alerts=alerts,

    total_alerts=len(alerts),

    high_count=high_count,

    medium_count=medium_count,

    low_count=low_count,

    info_count=info_count,

    nmap_results=nmap_results,

    total_ports=len(nmap_results)
)


    # =====================================================
    # HANDLE SCAN ERROR
    # =====================================================

    except Exception as e:

        print()
        print("========================================")
        print("SCAN ERROR")
        print("========================================")

        print(e)


        return render_template(
            "index.html",

            error=(
                "Scan failed. Make sure OWASP ZAP is running "
                "and the target website is available."
            ),

            zap_connected=check_zap_connection()
        )


# =========================================================
# START FLASK APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )