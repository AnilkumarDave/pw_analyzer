"""
PyQt6 GUI for pw_analyzer.py with a human-friendly summary
- Thread-safe: uses QThread + Worker QObject
- Adds a colored summary label showing classification + quick suggestion
- Exports human verdict into JSON/CSV
Run: python gui.py
"""
import sys
import json
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QFileDialog, QCheckBox,
    QSpinBox, QMessageBox, QDoubleSpinBox
)
from PyQt6.QtCore import Qt, QObject, QThread, pyqtSignal

# Import analyze_password from your script (pw_analyzer.py must be in same folder)
try:
    from pw_analyzer import analyze_password, load_wordlist
except Exception as e:
    analyze_password = None
    load_wordlist = None
    IMPORT_ERROR = e
else:
    IMPORT_ERROR = None


class Worker(QObject):
    """
    Worker runs analyze_password and emits finished(result, exception).
    """
    finished = pyqtSignal(object, object)  # (result, exception)

    def __init__(self, fn, pw, kwargs):
        super().__init__()
        self.fn = fn
        self.pw = pw
        self.kwargs = kwargs or {}

    def run(self):
        result = None
        exc = None
        try:
            result = self.fn(self.pw, **self.kwargs)
        except Exception as e:
            exc = e
        self.finished.emit(result, exc)


def build_human_summary(result: dict) -> (str, str, str):
    """
    Build a short human-readable summary and a slightly longer suggestions string.
    Returns (short_html, color, suggestions_text).
    """
    if not result:
        return ("No result", "#6c757d", "")

    cls = result.get("classification", "unknown").lower()
    entropy = result.get("entropy_bits", None)
    recs = result.get("recommendations", []) or []

    # short verdict + one-liner suggestion
    if cls == "weak":
        color = "#d9534f"  # red
        verdict = "Weak — change it"
        one = recs[0] if recs else "Increase length and complexity."
    elif cls == "medium":
        color = "#f0ad4e"  # orange
        verdict = "Medium — improve it"
        one = recs[0] if recs else "Add length and more character types."
    elif cls == "strong":
        color = "#5cb85c"  # green
        verdict = "Strong — good"
        one = recs[0] if recs else "Consider using a password manager."
    else:
        color = "#6c757d"  # gray
        verdict = "Unknown"
        one = recs[0] if recs else ""

    entropy_part = f" • Entropy: {entropy} bits" if entropy is not None else ""
    short_html = f'<div><b>{verdict}</b>{entropy_part}<div style="margin-top:6px">{one}</div></div>'
    sugg_text = "\n".join(f"- {s}" for s in recs) if recs else ""
    return (short_html, color, sugg_text)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Analyzer — GUI (with Summary)")
        self.setMinimumSize(860, 560)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)

        # Import check
        if IMPORT_ERROR:
            err_label = QLabel(f"Error importing pw_analyzer: {IMPORT_ERROR}")
            err_label.setStyleSheet("color: red;")
            layout.addWidget(err_label)

        # Password input
        pw_layout = QHBoxLayout()
        pw_label = QLabel("Password:")
        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Normal)
        self.pw_input.setPlaceholderText("Enter password to analyze")
        pw_layout.addWidget(pw_label)
        pw_layout.addWidget(self.pw_input)
        layout.addLayout(pw_layout)

        # Dictionary load and checkbox
        dict_layout = QHBoxLayout()
        self.dict_checkbox = QCheckBox("Use dictionary file")
        self.dict_checkbox.setChecked(False)
        self.dict_label = QLabel("No file selected")
        self.dict_button = QPushButton("Load dictionary")
        self.dict_button.clicked.connect(self.load_dict_file)
        dict_layout.addWidget(self.dict_checkbox)
        dict_layout.addWidget(self.dict_label)
        dict_layout.addWidget(self.dict_button)
        layout.addLayout(dict_layout)

        # Brute options
        brute_layout = QHBoxLayout()
        brute_layout.addWidget(QLabel("Max brute attempts:"))
        self.max_brute_spin = QSpinBox()
        self.max_brute_spin.setRange(10, 10_000_000)
        self.max_brute_spin.setValue(10000)
        brute_layout.addWidget(self.max_brute_spin)

        brute_layout.addWidget(QLabel("Brute max length:"))
        self.brute_len_spin = QSpinBox()
        self.brute_len_spin.setRange(1, 8)
        self.brute_len_spin.setValue(5)
        brute_layout.addWidget(self.brute_len_spin)

        brute_layout.addWidget(QLabel("Max seconds:"))
        self.max_seconds_spin = QDoubleSpinBox()
        self.max_seconds_spin.setRange(0.1, 30.0)
        self.max_seconds_spin.setSingleStep(0.1)
        self.max_seconds_spin.setValue(1.0)
        brute_layout.addWidget(self.max_seconds_spin)

        layout.addLayout(brute_layout)

        # Buttons
        btn_layout = QHBoxLayout()
        self.run_button = QPushButton("Analyze")
        self.run_button.clicked.connect(self.on_run)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.on_cancel)
        self.cancel_button.setEnabled(False)
        self.save_button = QPushButton("Save report")
        self.save_button.clicked.connect(self.on_save)
        self.save_button.setEnabled(False)
        btn_layout.addWidget(self.run_button)
        btn_layout.addWidget(self.cancel_button)
        btn_layout.addWidget(self.save_button)
        layout.addLayout(btn_layout)

        # Human-friendly summary (colored)
        self.summary_label = QLabel()
        self.summary_label.setWordWrap(True)
        self.summary_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.summary_label.setMinimumHeight(60)
        self.summary_label.setStyleSheet("background: #f8f9fa; border-radius: 6px; padding: 8px;")
        layout.addWidget(self.summary_label)

        # Results area (JSON)
        layout.addWidget(QLabel("Result (JSON):"))
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)

        # Internal state
        self.dict_path = None
        self.wordlist = None
        self.last_report = None

        # Thread tracking
        self._worker_thread = None
        self._worker = None

    def load_dict_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select dictionary file", str(Path.cwd()), "Text Files (*.txt);;All Files (*)"
        )
        if path:
            self.dict_path = path
            self.dict_label.setText(Path(path).name)
            self.dict_checkbox.setChecked(True)
            if load_wordlist:
                try:
                    self.wordlist = load_wordlist(path)
                    QMessageBox.information(
                        self, "Dictionary loaded", f"Loaded {len(self.wordlist)} words from {Path(path).name}"
                    )
                except Exception as e:
                    QMessageBox.warning(self, "Load failed", f"Could not load dictionary: {e}")
                    self.wordlist = None

    def on_run(self):
        if IMPORT_ERROR:
            QMessageBox.critical(self, "Import error", f"Cannot run — failed to import pw_analyzer:\n{IMPORT_ERROR}")
            return

        pw = self.pw_input.text().strip()
        if not pw:
            QMessageBox.warning(self, "No password", "Please enter a password to analyze.")
            return

        wordlist = self.wordlist if (self.dict_checkbox.isChecked() and self.wordlist) else None
        brute_charset = None
        max_brute = int(self.max_brute_spin.value())
        brute_max_len = int(self.brute_len_spin.value())
        max_seconds = float(self.max_seconds_spin.value())

        self.run_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.summary_label.setText("")
        self.result_text.setPlainText("Running analysis... (this may take a few seconds)")

        kwargs = {
            "wordlist": wordlist,
            "dict_mangling": True,
            "brute_charset": brute_charset,
            "max_brute_attempts": max_brute,
            "brute_max_len": brute_max_len,
            "max_seconds": max_seconds,
        }

        self._worker_thread = QThread()
        self._worker = Worker(analyze_password, pw, kwargs)
        self._worker.moveToThread(self._worker_thread)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker_thread.started.connect(self._worker.run)
        self._worker_thread.start()

    def on_cancel(self):
        if self._worker_thread and self._worker_thread.isRunning():
            self._worker_thread.requestInterruption()
            self._worker_thread.quit()
            self._worker_thread.wait(2000)
        self._worker_thread = None
        self._worker = None
        self.run_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.result_text.append("\nAnalysis cancelled.")

    def _on_worker_finished(self, result, exc):
        self.run_button.setEnabled(True)
        self.cancel_button.setEnabled(False)

        if self._worker_thread:
            self._worker_thread.quit()
            self._worker_thread.wait(2000)
            self._worker_thread = None
            self._worker = None

        if exc:
            self.summary_label.setText("")
            self.result_text.setPlainText(f"Error during analysis:\n{exc}")
            QMessageBox.critical(self, "Error", f"Exception during analysis:\n{exc}")
            self.last_report = None
            self.save_button.setEnabled(False)
            return

        try:
            pretty = json.dumps(result, indent=2)
        except Exception:
            pretty = str(result)
        self.result_text.setPlainText(pretty)
        self.last_report = [result]
        self.save_button.setEnabled(True)

        short_html, color, sugg_text = build_human_summary(result)
        style = f"background: #ffffff; border-left: 8px solid {color}; padding:8px; border-radius:6px;"
        self.summary_label.setStyleSheet(style)
        self.summary_label.setText(short_html)
        if sugg_text:
            self.result_text.append("\nSuggestions:\n" + sugg_text)

    def on_save(self):
        if not self.last_report:
            return

        enriched = []
        for r in self.last_report:
            short_html, _, _ = build_human_summary(r)
            verdict_text = (
                short_html.replace("<div>", "")
                .replace("</div>", "")
                .replace("<b>", "")
                .replace("</b>", "")
            )
            verdict_text = verdict_text.split("•")[0].strip()
            new_r = dict(r)
            new_r["human_verdict"] = verdict_text
            enriched.append(new_r)

        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save report",
            str(Path.cwd() / "report.json"),
            "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)"
        )

        if not path:
            return

        try:
            if path.lower().endswith(".csv") or "CSV" in selected_filter:
                import csv
                keys = ["password", "classification", "entropy_bits", "length", "human_verdict"]
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    for r in enriched:
                        row = {k: r.get(k, "") for k in keys}
                        writer.writerow(row)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(enriched, f, indent=2)

            QMessageBox.information(self, "Saved", f"Saved report to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Save failed", f"Could not save report: {e}")


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
