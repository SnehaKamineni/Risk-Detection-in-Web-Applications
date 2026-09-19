from zapv2 import ZAPv2
import time


# =========================================================
# ZAP CONFIGURATION
# =========================================================

# Copy your current API key from:
# OWASP ZAP -> Tools -> Options -> API
API_KEY = "30756ujko3vvadgc7ig86rrdck"


proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080"
}


zap = ZAPv2(
    apikey=API_KEY,
    proxies=proxies
)


# =========================================================
# TARGET
# =========================================================

target = "http://127.0.0.1:5001"

# Our custom ZAP scan policy
SCAN_POLICY = "WebShield Policy"


try:

    # =====================================================
    # TEST ZAP CONNECTION
    # =====================================================

    print(
        "ZAP Version:",
        zap.core.version
    )


    # =====================================================
    # OPEN TARGET
    # =====================================================

    print("\nOpening target...")

    zap.urlopen(target)

    time.sleep(2)


    # =====================================================
    # OPEN SEARCH ENDPOINT
    # =====================================================

    # This helps ZAP learn that the application
    # contains a 'query' parameter.

    search_url = (
        target +
        "/search?query=test"
    )

    print(
        "Opening search endpoint..."
    )

    zap.urlopen(search_url)

    time.sleep(2)


    # =====================================================
    # SPIDER SCAN
    # =====================================================

    print(
        "\nStarting Spider..."
    )

    spider_id = zap.spider.scan(
        target
    )


    while int(
        zap.spider.status(spider_id)
    ) < 100:

        status = zap.spider.status(
            spider_id
        )

        print(
            "Spider Progress:",
            status + "%"
        )

        time.sleep(2)


    print(
        "Spider Completed!"
    )


    # =====================================================
    # DISCOVERED URLS
    # =====================================================

    urls = zap.spider.results(
        spider_id
    )


    print(
        "\nURLs Found:",
        len(urls)
    )


    for discovered_url in urls:

        print(
            discovered_url
        )


    # =====================================================
    # ACTIVE SCAN
    # =====================================================

    print(
        "\nStarting Active Scan..."
    )

    print(
        "Using Scan Policy:",
        SCAN_POLICY
    )


    active_scan_id = zap.ascan.scan(
        target,
        scanpolicyname=SCAN_POLICY
    )


    while int(
        zap.ascan.status(active_scan_id)
    ) < 100:

        status = zap.ascan.status(
            active_scan_id
        )

        print(
            "Active Scan Progress:",
            status + "%"
        )

        time.sleep(2)


    print(
        "Active Scan Completed!"
    )


    # =====================================================
    # FINAL RESULTS
    # =====================================================

    alerts = zap.core.alerts(
        baseurl=target
    )


    print(
        "\n================================="
    )

    print(
        "FINAL SECURITY RESULTS"
    )

    print(
        "================================="
    )


    print(
        "Total Vulnerabilities:",
        len(alerts)
    )


    # =====================================================
    # DISPLAY EACH VULNERABILITY
    # =====================================================

    if len(alerts) == 0:

        print(
            "\nNo vulnerabilities detected."
        )


    else:

        for index, alert in enumerate(
            alerts,
            start=1
        ):

            print(
                "\n---------------------------------"
            )

            print(
                "Alert Number:",
                index
            )

            print(
                "Vulnerability:",
                alert.get(
                    "alert",
                    "Unknown"
                )
            )

            print(
                "Risk:",
                alert.get(
                    "risk",
                    "Unknown"
                )
            )

            print(
                "URL:",
                alert.get(
                    "url",
                    "Unknown"
                )
            )

            print(
                "Parameter:",
                alert.get(
                    "param",
                    "Not available"
                )
            )

            print(
                "Description:",
                alert.get(
                    "description",
                    "No description available."
                )
            )

            print(
                "Solution:",
                alert.get(
                    "solution",
                    "No solution available."
                )
            )


# =========================================================
# ERROR HANDLING
# =========================================================

except Exception as error:

    print(
        "\n================================="
    )

    print(
        "SCAN ERROR"
    )

    print(
        "================================="
    )

    print(error)

    print(
        "\nMake sure:"
    )

    print(
        "1. OWASP ZAP is running."
    )

    print(
        "2. test_target.py is running on port 5001."
    )

    print(
        "3. Your ZAP API key is correct."
    )

    print(
        '4. "WebShield Policy" exists in ZAP.'
    )