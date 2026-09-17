# 🛡️ WebShield – Intelligent Web Application Security Assessment System

WebShield is an intelligent web application security assessment system designed to identify, analyze, and present security vulnerabilities in web applications.

The system integrates multiple cybersecurity tools to perform web application and network security analysis. It provides detected vulnerabilities, severity levels, affected URLs, vulnerability descriptions, and recommended solutions through a user-friendly dashboard.

---

## 📌 Project Objective

The main objective of WebShield is to automate the process of identifying security weaknesses in web applications.

The system is designed to:

- Scan web applications for common security vulnerabilities
- Detect vulnerabilities related to the OWASP Top 10
- Analyze network ports and running services
- Classify vulnerabilities according to severity
- Display vulnerability descriptions and affected URLs
- Provide recommended security solutions
- Reduce the manual effort involved in security assessment

---

## 🔍 Current Features

### 1. Web Application Security Scanning

WebShield integrates **OWASP ZAP (Zed Attack Proxy)** for Dynamic Application Security Testing (DAST).

The current implementation supports:

- Spider-based URL discovery
- Active security scanning
- Vulnerability detection
- Severity analysis
- Identification of affected URLs
- Vulnerability descriptions
- Recommended solutions

Examples of security issues that may be identified by ZAP include:

- Cross-Site Scripting (XSS)
- Missing Content Security Policy (CSP)
- Missing Anti-Clickjacking Headers
- Missing X-Content-Type-Options Header
- Server Version Information Disclosure
- HTTP security-related issues

---

### 2. Network and Service Analysis

WebShield integrates **Nmap** for network and service analysis.

The current prototype can obtain information such as:

- Target host
- Port number
- Protocol
- Port state
- Running service
- Product information
- Service version
- Additional service information

The current Review-1 prototype validates Nmap integration using the authorized local test application's port.

---

### 3. Severity Analysis

Detected ZAP findings are grouped according to their security severity.

The dashboard currently displays:

- High Risk
- Medium Risk
- Low Risk
- Informational findings

This allows users to understand the severity of the detected security issues.

---

### 4. Security Assessment Dashboard

WebShield provides a web-based interface developed using Flask, HTML, and CSS.

The results page displays:

- Total findings
- Number of High-risk findings
- Number of Medium-risk findings
- Number of Low-risk findings
- Individual vulnerability details
- Affected URL
- Vulnerability description
- Recommended solution
- Nmap network and service information

Users can navigate through individual vulnerability alerts using Previous and Next controls.

---

## ⚙️ Current Workflow

```text
Target Web Application
        |
        v
+-----------------------+
|   Security Scanning   |
+-----------------------+
        |
        +--------------------+
        |                    |
        v                    v
+---------------+     +---------------+
|   OWASP ZAP   |     |     Nmap      |
|     DAST      |     | Network Scan  |
+---------------+     +---------------+
        |                    |
        v                    v
Web Vulnerabilities     Port & Service
        |               Information
        +---------+----------+
                  |
                  v
        +-------------------+
        | WebShield Results |
        |     Dashboard     |
        +-------------------+
```

---

## 🛠️ Technologies Used

### Frontend

- HTML
- CSS
- JavaScript

### Backend

- Python
- Flask

### Security Tools

- OWASP ZAP
- Nmap

### Planned Security Tool

- Semgrep

### Planned Machine Learning

- Scikit-learn
- Random Forest / XGBoost

### Planned Database

- SQLite / MySQL

### Data Processing

- Pandas
- NumPy

---

## 📂 Project Structure

```text
hcl project/
│
├── app.py
├── nmap_scanner.py
├── test_target.py
├── test_zap.py
├── test_nmap.py
├── README.md
├── .gitignore
│
├── templates/
│   ├── index.html
│   └── scan_result.html
│
├── static/
│   └── style.css
│
└── venv/
```

> The `venv` directory is used locally and should not be uploaded to GitHub.

---

## 🚀 How to Run the Current Prototype

### Prerequisites

Install the following before running the project:

- Python 3
- Flask
- OWASP ZAP
- Nmap
- Python OWASP ZAP client

---

### 1. Start OWASP ZAP

Open the OWASP ZAP Desktop application and make sure the ZAP API is available.

Do not store or publish your real ZAP API key in the GitHub repository.

---

### 2. Activate the Python Virtual Environment

On Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

---

### 3. Start the Local Test Application

```powershell
python test_target.py
```

The authorized local test application runs at:

```text
http://127.0.0.1:5001
```

---

### 4. Start WebShield

Open another terminal, activate the virtual environment, and run:

```powershell
python app.py
```

WebShield runs at:

```text
http://127.0.0.1:5000
```

---

### 5. Start a Security Assessment

Open WebShield in the browser.

For the current local demonstration, enter:

```text
http://127.0.0.1:5001
```

Then select **Start Scan**.

WebShield performs the configured security assessment and displays the results on the dashboard.

---

## 🧪 Current Review-1 Implementation

The following modules have been implemented and tested:

- WebShield Flask application
- Security assessment user interface
- Authorized local vulnerable test application
- OWASP ZAP API integration
- ZAP Spider integration
- ZAP Active Scan integration
- Custom WebShield ZAP scan policy
- Vulnerability extraction
- Severity counting
- Vulnerability description display
- Recommended solution display
- Nmap integration
- Nmap XML result parsing
- Network/service information extraction
- Combined ZAP and Nmap results dashboard

---

## 🔮 Future Enhancements

The next stages of the project are planned to include:

### Semgrep Integration

Semgrep will be used for **Static Application Security Testing (SAST)** to analyze source code and identify insecure coding patterns.

### Machine Learning Risk Classification

Security information collected from the scanning tools will be processed and used for ML-based risk classification.

Planned risk categories:

```text
Low
Medium
High
Critical
```

Possible ML algorithms include:

- Random Forest
- XGBoost

### Improved Security Suggestions

The system will provide clear suggestions for detected vulnerabilities to help developers understand how security weaknesses can be mitigated.

### Automated Security Report

A report-generation module is planned to produce a structured security assessment report containing:

- Detected vulnerabilities
- Risk levels
- Affected components
- Security impact
- Recommended solutions
- Network/service findings

---

## 🎯 Expected Final System

The final WebShield system is intended to combine:

```text
OWASP ZAP
    +
Nmap
    +
Semgrep
    |
    v
Security Data Collection
    |
    v
Data Processing
    |
    v
Machine Learning
    |
    v
Risk Classification
    |
    v
Suggestions for Detected Vulnerabilities
    |
    v
Security Assessment Report
```

---

## ⚠️ Ethical Use

WebShield is intended for:

- Educational purposes
- Authorized security testing
- Security research
- Testing applications owned by the user or applications for which explicit authorization has been obtained

Do not use this project to scan systems without permission.

---

## 🔐 Security Note

Never commit sensitive information such as:

- OWASP ZAP API keys
- Passwords
- Database credentials
- API secrets
- Private configuration files

Sensitive configuration should be stored securely using environment variables or files excluded through `.gitignore`.

---

## 📈 Project Status

**Current Stage:** Review 1 Prototype

**Completed:**

OWASP ZAP Integration ✅  
Nmap Integration ✅  
Web Vulnerability Detection ✅  
Severity Analysis ✅  
Network & Service Detection ✅  
Web-Based Results Dashboard ✅  

**Next Development:**

Semgrep SAST Integration ⏳  
Machine Learning Risk Classification ⏳  
Improved Suggestions ⏳  
Automated Security Report Generation ⏳  

---

## 👩‍💻 Project

**WebShield – Intelligent Web Application Security Assessment System**

B.Tech CSE (Cyber Security) Major Project