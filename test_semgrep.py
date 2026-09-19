from semgrep_scanner import run_semgrep_scan

target = "test_target.py"

print("Starting Semgrep Scan...")
print("--------------------------------")

results = run_semgrep_scan(target)

print("\nSemgrep Findings:", len(results))

for index, finding in enumerate(results, start=1):
    print("\n--------------------------------")
    print("Finding:", index)
    print("Rule:", finding["check_id"])
    print("File:", finding["path"])
    print("Line:", finding["start_line"])
    print("Severity:", finding["severity"])
    print("Message:", finding["message"])
