# ⚠️ Risk & Issue Log — Password Analyzer

_This log identifies potential risks and issues encountered during the Password Analyzer project, along with their likelihood, impact, and mitigation steps._

---

| **ID** | **Risk / Issue** | **Category** | **Likelihood** | **Impact** | **Mitigation / Action** | **Status** |
|:-------|:-----------------|:--------------|:---------------|:------------|:------------------------|:-----------|
| **R1** | Long brute-force computation may freeze program | Technical | Medium | High | Implemented `max_seconds`, user-configurable `max_brute_attempts` and `brute_max_len` | ✅ Mitigated |
| **R2** | User enters empty or invalid passwords | Functional | High | Medium | GUI and CLI validation; shows error messages | ✅ Mitigated |
| **R3** | Dictionary file missing or unreadable | Technical | Medium | Medium | Added file existence checks, exception handling, fallback to no dictionary | ✅ Mitigated |
| **R4** | Users misunderstand strength verdict | Usability | Medium | Medium | Added colored, human-friendly summary with one-line verdict | ✅ Mitigated |
| **R5** | Misinterpretation of output as real security advice | Compliance / Legal | Medium | High | Added disclaimer in `README.md`: for educational/demo purposes only | ✅ Mitigated |

---

_**Note:** All identified risks were mitigated through design improvements, exception handling, and user-facing disclaimers._
