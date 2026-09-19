import subprocess
import json
import os


def run_semgrep_scan(target_path):
    semgrep_dir = r"C:\Users\sneha\AppData\Roaming\Python\Python312\Scripts"
    semgrep_exe = os.path.join(semgrep_dir, "semgrep.exe")

    environment = os.environ.copy()

    # Make sure Semgrep can find pysemgrep.exe
    environment["PATH"] = (
        semgrep_dir
        + os.pathsep
        + environment.get("PATH", "")
    )

    command = [
        semgrep_exe,
        "--config", "auto",
        "--json",
        target_path
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            env=environment
        )

        if process.returncode not in (0, 1):
            print("Semgrep scan failed.")
            print(process.stderr)
            return []

        if not process.stdout.strip():
            return []

        data = json.loads(process.stdout)

        results = []

        for finding in data.get("results", []):
            results.append({
                "check_id": finding.get(
                    "check_id",
                    "Unknown"
                ),
                "path": finding.get(
                    "path",
                    "Unknown"
                ),
                "start_line": finding.get(
                    "start",
                    {}
                ).get(
                    "line",
                    0
                ),
                "end_line": finding.get(
                    "end",
                    {}
                ).get(
                    "line",
                    0
                ),
                "message": finding.get(
                    "extra",
                    {}
                ).get(
                    "message",
                    "No description available."
                ),
                "severity": finding.get(
                    "extra",
                    {}
                ).get(
                    "severity",
                    "INFO"
                )
            })

        return results

    except subprocess.TimeoutExpired:
        print("Semgrep scan timed out.")
        return []

    except json.JSONDecodeError:
        print("Could not parse Semgrep JSON output.")
        return []

    except Exception as error:
        print("Semgrep scan failed:", error)
        return []