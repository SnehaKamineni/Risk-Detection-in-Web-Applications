import subprocess
import xml.etree.ElementTree as ET


def run_nmap_scan(target):
    command = [
        "nmap",
        "-sT",
        "-sV",
        "-Pn",
        "-n",
        "-p",
        "5001",
        "-oX",
        "-",
        target
    ]

    results = []

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        if process.returncode != 0:
            print("Nmap scan failed:")
            print(process.stderr)
            return results

        root = ET.fromstring(process.stdout)

        for host in root.findall("host"):

            address_element = host.find("address")

            if address_element is not None:
                host_address = address_element.get("addr")
            else:
                host_address = target

            ports_element = host.find("ports")

            if ports_element is None:
                continue

            for port in ports_element.findall("port"):

                state_element = port.find("state")
                service_element = port.find("service")

                scan_result = {
                    "host": host_address,
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),

                    "state": (
                        state_element.get("state")
                        if state_element is not None
                        else "Unknown"
                    ),

                    "service": (
                        service_element.get("name", "Unknown")
                        if service_element is not None
                        else "Unknown"
                    ),

                    "product": (
                        service_element.get("product", "Unknown")
                        if service_element is not None
                        else "Unknown"
                    ),

                    "version": (
                        service_element.get("version", "Unknown")
                        if service_element is not None
                        else "Unknown"
                    ),

                    "extra_info": (
                        service_element.get("extrainfo", "")
                        if service_element is not None
                        else ""
                    )
                }

                results.append(scan_result)

        return results

    except subprocess.TimeoutExpired:
        print("Nmap scan timed out.")
        return results

    except ET.ParseError:
        print("Could not parse Nmap XML.")
        return results

    except Exception as error:
        print("Nmap scan failed:", error)
        return results