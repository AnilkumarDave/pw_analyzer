"""Example pytest tests for the Password Analyzer core functions.

Anil can adapt the imports and function names to match his actual implementation
in `pw_analyzer.py`. The important part is to have a small but meaningful suite
of automated tests that can be demonstrated and extended.
"""

import pytest

# Update this import to match the real module and function names
# from pw_analyzer import analyze_password


def dummy_analyze_password(pw: str):
    """Placeholder implementation.

    Replace this with a call to the real analyze_password function.
    The expected return value is a dict with at least:
      - score (int)
      - strength_label (str)
      - breached (bool)
    """
    score = 0
    if len(pw) >= 12:
        score += 2
    if any(c.islower() for c in pw):
        score += 1
    if any(c.isupper() for c in pw):
        score += 1
    if any(c.isdigit() for c in pw):
        score += 1

    if score <= 1:
        label = "Very Weak"
    elif score == 2:
        label = "Weak"
    elif score == 3:
        label = "Medium"
    else:
        label = "Strong"

    breached = pw.lower() in {"password", "123456", "qwerty"}

    return {
        "score": score,
        "strength_label": label,
        "breached": breached,
    }


@pytest.mark.parametrize(
    "password, expected_label",
    [
        ("123456", "Very Weak"),
        ("password", "Very Weak"),
        ("abcdEF12", "Medium"),
        ("Str0ngPass!2025", "Strong"),
    ],
)
def test_password_strength_labels(password, expected_label):
    # Replace dummy_analyze_password with analyze_password from the real module
    result = dummy_analyze_password(password)
    assert result["strength_label"] == expected_label


def test_breached_passwords_are_flagged():
    # Replace dummy_analyze_password with analyze_password from the real module
    result = dummy_analyze_password("password")
    assert result["breached"] is True


def test_non_breached_passwords_are_not_flagged():
    # Replace dummy_analyze_password with analyze_password from the real module
    result = dummy_analyze_password("UniquePassw0rd!2025")
    assert result["breached"] is False
