# Progress Log — Password Analyzer (MSc Project, UEL)

> _This log is reconstructed in October 2025 from memory, code commits, notes, and emails. Hours shown reflect my own effort, not team totals. This is for transparency, not an exact time sheet._

---

## Week 1 (5–10 Oct 2022)

| Date(s) | Activity | Category | Est. Hours | Notes |
|----------|-----------|-----------|-------------|--------|
| 5–10 Oct 2022 | Initial project discussion with Prof. Abdulrazaq Abba; defined objectives, scope, and deliverables | PLAN | 4 | Project not mandatory, extra-curricular |
| 5–10 Oct 2022 | Setup project repository structure; basic Python environment configuration | DEV | 3 | Installed venv, created folders for data, scripts, docs |
| 5–10 Oct 2022 | Research password strength metrics, entropy calculation, and dictionary attacks | RES | 4 | Collected references and sample datasets |

**Week total:** ~11 hrs  

---

## Week 2 (11–15 Oct 2022)

| Date(s) | Activity | Category | Est. Hours | Notes |
|----------|-----------|-----------|-------------|--------|
| 11–12 Oct 2022 | Implemented entropy-based password strength estimation | DEV | 6 | Functions to compute charset size, entropy in bits |
| 13 Oct 2022 | Added heuristic checks for common patterns (repeated chars, sequential, year-like passwords) | DEV | 4 | Tested with sample passwords |
| 14–15 Oct 2022 | Started dictionary attack simulation with wordlist & mangling | DEV | 5 | Limited to 100k checks for performance |

**Week total:** ~15 hrs  

---

## Week 3 (16–20 Oct 2022)

| Date(s) | Activity | Category | Est. Hours | Notes |
|----------|-----------|-----------|-------------|--------|
| 16–17 Oct 2022 | Developed limited brute-force simulation (configurable charset & length) | DEV | 6 | Included `max_seconds` parameter for timeout |
| 18 Oct 2022 | Integrated reporting system (JSON, CSV, plain text) | DEV | 4 | Flattened results for easier export |
| 19–20 Oct 2022 | Testing, debugging, and preparing project documentation | QA | 6 | Verified entropy calculations and attack simulations |

**Week total:** ~16 hrs  

---

## Summary

**Total reconstructed hours:** ~42 hrs  

| Category | Description |
|-----------|-------------|
| PLAN | Planning & scope definition |
| RES | Research & references |
| DEV | Development / coding |
| QA | Quality checks & debugging |
| TEST | Running simulations, verifying outputs |

