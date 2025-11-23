# 🛡️ Password Analyzer & Breach Simulation (Academic Project – MSc Information Security & Digital Forensics)

📅 **Project Duration:** 5 October 2022 – 20 October 2022 (≈ 15 days, Part-Time)  
Academic Year: First Term (MSc Information Security & Digital Forensics)  
Institution: University of East London, London, UK    
Subject: Computer Security

---

## 🏫 Project Overview
This project was created as part of my MSc in Information Security and Digital Forensics
and later refined as a portfolio project.

It is a Python-based tool that helps users understand the strength of passwords and
whether they may have appeared in known or simulated data breaches.

**Key features:**  

- A command-line interface (CLI) for quick checks
- A simple GUI (for example using PyQt6) for interactive use
- Password strength analysis based on length, character sets and common patterns
- Checks against a local list of breached passwords (or hash prefixes), simulating
  real-world breach lookups
- CSV/JSON export of results for further review

The core logic is written in **Python**, with a focus on clear, testable functions.

In October 2025, the project was modernised for Python 3.13 with improved report structure and optional GUI.

---

## 🎯 Project Objectives
- Demonstrate secure handling of passwords in a learning environment (no plain-text
  storage of real user passwords)
- Show how to structure a small security tool with both CLI and GUI entry points
- Provide simple reports that can be used for awareness and training
- Practise automated testing of security-related logic 

---

## ⚙️ Modernisation Note
| Originally Built | Modernised & Uploaded |
|-----------------|---------------------|
| Oct 2022        | Oct 2025            |

🛠️ Core Technologies

- Python 3  
- Standard library modules for hashing and file handling  
- Optional GUI built with PyQt6 or similar toolkit  
- CSV and/or JSON output for reporting  
- Automated tests written in **pytest** with **Allure** reports for visibility  

📂 Project Structure (typical)

- `pw_analyzer.py` – core password analysis functions and CLI entry point  
- `gui_app.py` (optional) – simple GUI wrapper using PyQt6 or similar  
- `data/breached_passwords.txt` – simulated breached password list  
- `reports/` – CSV/JSON reports created by the tool  
- `tests/` – automated tests for core functions (pytest + Allure)  
- `README.md` – project documentation (this file)  

🔍 What the Analyzer Does (Examples)

The exact implementation can vary, but typical checks include:

- **Strength analysis**
  - Minimum length checks
  - Presence of upper/lowercase letters, digits and symbols
  - Detection of common patterns (simple sequences, repeated characters, dictionary words)
- **Breach simulation**
  - Hashing the password and checking against a local breach list, or
  - Comparing against a file of known weak/breached passwords

The tool then produces a simple structured result such as:

- `score` – numeric strength score  
- `strength_label` – e.g. "Weak", "Medium", "Strong"  
- `breached` – boolean indicating whether it appears in the breach list  
- `reasons` – list of messages explaining the result  

## ▶️ Usage (Example)

Command-line usage (example, to be aligned with the actual script):

```bash
python pw_analyzer.py --password "ExamplePassword123!" --output reports/result.json
```

or to run in interactive/GUI mode:

```bash
python gui_app.py
```

The CLI can also be extended to read passwords from a file and write multiple results
to CSV or JSON.

## 🧪 Automated Testing & Allure Reports

The `tests/` folder contains automated tests for the core password analysis logic,
using **pytest** and **allure-pytest**.

These tests:

- Verify that very weak passwords are flagged correctly  
- Check that strong passwords reach the expected score/label range  
- Confirm that known breached passwords are marked as `breached=True`  
- Provide a safety net when refactoring or extending the tool

To run the tests locally (from the project root after installing test dependencies):

```bash
pip install -r requirements-tests.txt
pytest --alluredir=allure-results
```

To generate and view an Allure HTML report:

```bash
allure serve allure-results
```

This produces a visual test report showing which cases passed/failed and gives a
clear picture of coverage for interview or review purposes.

## 🧵 CI Integration (Optional)

A simple CI pipeline (for example in Jenkins or GitHub Actions) can:

1. Check out the repository  
2. Install dependencies (including test dependencies)  
3. Run `pytest --alluredir=allure-results`  
4. Archive the Allure results or publish an HTML report  

This demonstrates how even a small security tool can benefit from CI and automated testing.

---

## ⚠️ Limitations
| Limitation                     | Description | Possible Improvement |
|--------------------------------|-------------|--------------------|
| Limited brute-force             | Stops after configured attempts / time | Implement GPU-based attacks or distributed brute-force |
| Dictionary attack depends on wordlist | Weak passwords outside the wordlist won’t be detected | Use larger or dynamic breached password lists |
| GUI requires PyQt6              | Optional but adds dependencies | Provide web-based interface |

---

## 🌟 Advantages
✅ Multi-layer password security evaluation  
✅ Human-readable recommendations  
✅ Structured JSON/CSV reports for research or portfolio purposes  
✅ Thread-safe PyQt6 GUI for interactive testing  
✅ Demonstrates Python programming, security heuristics, and report generation  

---

## ⏱️ Project Timeline
| Week / Day       | Task |
|-----------------|------|
| 5 Oct 2022      | Requirement analysis & planning |
| 6–10 Oct 2022   | Python module development (`pw_analyzer.py`) |
| 11–15 Oct 2022  | Testing dictionary & brute-force simulations |
| 16–18 Oct 2022  | Add recommendations, report formatting |
| 19 Oct 2022     | Optional GUI (`gui.py`) development |
| 20 Oct 2022     | Final testing, documentation, and submission |

---

## 🔮 Future Scope
- Real-time integration with breached password databases  
- Web-based dashboard for analysis and visualization  
- GPU-accelerated brute-force simulations  
- Improved dictionary mangling and heuristic rules  
- Continuous updates with new password security guidelines  

---

## 🚀 Quick Setup
```bash
# Clone repository
git clone https://github.com/<yourusername>/pw-analyzer.git
cd pw-analyzer

# Create virtual environment
python -m venv .venv
# Activate environment
.\.venv\Scripts\activate      # Windows
source .venv/bin/activate     # Linux / macOS

# Install dependencies if any
pip install -r requirements.txt

# Run CLI analysis (single password)
python pw_analyzer.py --password "P@ssw0rd123" --report out.json

# Run batch analysis
python pw_analyzer.py --batch passwords.txt --dict common.txt --report report.csv

# Optional: Run GUI
python gui.py

📜 Disclaimer

This project is intended for educational and demonstration purposes only. It should not be used as a sole basis for password security decisions or as a substitute for organisational security policies and guidance.

✨ Author

Name: Anilkumar Dave
Email: daveanil48@gmail.com
