# 🛡️ Password Analyzer & Breach Simulation (Academic Project – MSc Information Security & Digital Forensics)

📅 **Project Duration:** 5 October 2022 – 20 October 2022 (≈ 15 days, Part-Time)  
Academic Year: First Term (MSc Information Security & Digital Forensics)  
Institution: University of East London, London, UK    
Subject: Computer Security

---

## 🏫 Project Overview
This project was built as an **extra-curricular academic project** during my MSc.  

It is a **Python-based password strength analyzer and breach simulation tool** that evaluates password complexity, simulates dictionary attacks and limited brute-force attacks, and produces structured reports.

**Key features:**  

- Password strength classification (Weak / Medium / Strong)  
- Entropy estimation (bits)  
- Dictionary attack simulation with optional mangling  
- Limited brute-force attack simulation  
- Human-friendly summary with actionable recommendations  
- Save analysis reports in **JSON** and **CSV** formats  
- Optional GUI using PyQt6 for interactive analysis  

In October 2025, the project was modernised for Python 3.13 with improved report structure and optional GUI.

---

## 🎯 Project Objectives
- Evaluate and classify password strength using entropy and heuristic rules  
- Simulate dictionary attacks and mangling techniques to detect weak passwords  
- Perform limited brute-force simulations with configurable parameters  
- Generate human-readable and machine-friendly reports  
- Provide recommendations to improve password security  

---

## ⚙️ Modernisation Note
| Originally Built | Modernised & Uploaded |
|-----------------|---------------------|
| Oct 2022        | Oct 2025            |

**Modern updates include:**  
✅ Updated Python code to Python 3.13  
✅ Enhanced dictionary attack mangling  
✅ Limited brute-force simulation with configurable attempts and max seconds  
✅ Added human-friendly verdicts to JSON/CSV reports  
✅ Cleaned folder structure and project documentation  
✅ Optional PyQt6 GUI for interactive analysis  

---

## 🧩 System Features

### 👨‍💻 CLI Version
- Analyze single or batch passwords  
- Produce JSON and CSV reports  
- Configure dictionary, brute-force charset, max attempts, and max length  

### 🧑‍💻 GUI Version (Optional)
- Interactive password analysis  
- Display human-friendly summary with color-coded verdict  
- Load dictionary file for attacks  
- Save reports including human verdict  

---

## 📂 Sample Data
| Category           | Examples / Notes |
|-------------------|-----------------|
| Passwords          | `P@ssw0rd123`, `123456`, `password` |
| Dictionary file    | `common.txt` (user-provided) |
| Reports            | JSON / CSV with human-friendly verdict |

---

## 💻 Project Files
| File                  | Description |
|----------------------|-------------|
| `pw_analyzer.py`      | Core Python module for password analysis |
| `gui.py`              | Optional PyQt6 GUI |
| `examples/`           | Sample password lists and dictionary files |
| `README.md`           | Project documentation |

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

This project was built as an extra-curricular MSc project. It is intended for educational, research, and password security awareness purposes only. Not intended for malicious use.

✨ Author

Name: Anilkumar Dave
Email: daveanil48@gmail.com
