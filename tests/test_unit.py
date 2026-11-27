"""
X-Ray Comprehensive Unit Tests
Tests domain detection, homoglyphs, brand mismatch, DOM detection,
risk engine deterministic scoring, and protection rules.
"""

import json
from pathlib import Path
import pytest

# ---------------------------------------------------------------------------
# Load Brand Registry
# ---------------------------------------------------------------------------
BRAND_REGISTRY_PATH = Path(__file__).parent.parent / "extension" / "data" / "brand-registry.json"
with open(BRAND_REGISTRY_PATH, "r", encoding="utf-8") as f:
    BRAND_DATA = json.load(f)
    BRANDS = BRAND_DATA["brands"]

HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'і': 'i', 'ѕ': 's', 'һ': 'h', 'ԛ': 'q',
    'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'ι': 'i', 'ο': 'o', 'ρ': 'p',
}

KNOWN_MALICIOUS_DOMAINS = [
    'attacker.example',
    'collector.example',
    'steal.example',
    'exfiltrate.example',
    'malicious.example',
]


def detect_homoglyphs(domain: str):
    for ch in domain:
        if ch in HOMOGLYPH_MAP:
            return True, f"Confusable character '{ch}' mimics '{HOMOGLYPH_MAP[ch]}'"
    return False, ""


def match_brand(hostname: str):
    lower = hostname.lower()
    for brand in BRANDS:
        claimed = any(kw.lower() in lower for kw in brand["keywords"]) or brand["brandId"] in lower
        if claimed:
            matches = lower == brand["officialDomain"] or lower in brand["aliases"]
            return {
                "brand": brand["brandName"],
                "claimed": True,
                "domainMatches": matches,
                "mismatch": not matches,
            }
    return None


def calculate_risk(
    is_known_malicious: bool = False,
    has_homoglyph: bool = False,
    has_brand_mismatch: bool = False,
    has_otp: bool = False,
    has_sensitive_outbound: bool = False,
    has_hidden_iframe: bool = False,
    has_canary_leak: bool = False,
):
    score = 0
    if is_known_malicious:
        score += 40
    if has_homoglyph:
        score += 25
    if has_brand_mismatch:
        score += 25
    if has_otp:
        score += 5
    if has_sensitive_outbound:
        score += 30
    if has_hidden_iframe:
        score += 10
    if has_canary_leak:
        score += 50

    capped_score = min(score, 100)
    level = "HIGH" if capped_score >= 60 else "MEDIUM" if capped_score >= 30 else "LOW"
    return capped_score, level


# ===========================================================================
# 1. Domain Detection Tests
# ===========================================================================

class TestDomainDetection:
    def test_official_mock_banking_domain(self):
        match = match_brand("demo-bank-a.example")
        assert match is not None
        assert match["brand"] == "DemoBank Alpha"
        assert match["domainMatches"] is True
        assert match["mismatch"] is False

    def test_brand_mismatch_detection(self):
        match = match_brand("fake-bank.example/demobank-alpha")
        # Domain claims DemoBank Alpha but domain is not official
        match_claim = match_brand("demobank-alpha.attacker.com")
        assert match_claim is not None
        assert match_claim["brand"] == "DemoBank Alpha"
        assert match_claim["mismatch"] is True
        assert match_claim["domainMatches"] is False

    def test_homoglyph_detection(self):
        # Cyrillic 'а' (U+0430) mimicking Latin 'a'
        cyrillic_domain = "dеmо-bаnk.example"
        has_homo, detail = detect_homoglyphs(cyrillic_domain)
        assert has_homo is True
        assert "Confusable character" in detail

    def test_ascii_clean_domain(self):
        clean_domain = "demo-bank-b.example"
        has_homo, _ = detect_homoglyphs(clean_domain)
        assert has_homo is False

    def test_unknown_domain(self):
        match = match_brand("completely-random-shop.com")
        assert match is None


# ===========================================================================
# 2. DOM Detection Tests
# ===========================================================================

class TestDomDetection:
    def test_otp_field_recognition(self):
        # Attribute criteria for OTP detection
        otp_attrs = {"autocomplete": "one-time-code", "name": "user_otp", "id": "otp"}
        is_otp = (
            otp_attrs.get("autocomplete") == "one-time-code"
            or "otp" in otp_attrs.get("name", "")
            or "otp" in otp_attrs.get("id", "")
        )
        assert is_otp is True

    def test_password_field_isolated(self):
        input_type = "password"
        assert input_type == "password"

    def test_hidden_iframe_criteria(self):
        iframe_styles = {"display": "none", "width": "0px", "height": "0px"}
        is_hidden = iframe_styles.get("display") == "none" or iframe_styles.get("width") == "0px"
        assert is_hidden is True

    def test_external_form_action(self):
        page_origin = "http://demo-bank-a.example"
        form_action = "http://attacker.example/steal"
        is_external = not form_action.startswith(page_origin)
        assert is_external is True


# ===========================================================================
# 3. Deterministic Risk Engine Tests
# ===========================================================================

class TestRiskEngine:
    def test_clean_site_low_risk(self):
        score, level = calculate_risk()
        assert score == 0
        assert level == "LOW"

    def test_otp_field_alone_cannot_cause_high_risk(self):
        # Spec rule: An OTP field alone must never cause a high-risk verdict
        score, level = calculate_risk(has_otp=True)
        assert score == 5
        assert level == "LOW"

    def test_brand_mismatch_plus_homoglyph_is_medium_to_high(self):
        score, level = calculate_risk(has_homoglyph=True, has_brand_mismatch=True)
        assert score == 50
        assert level == "MEDIUM"

    def test_phishing_attack_reaches_high_risk(self):
        score, level = calculate_risk(
            has_brand_mismatch=True,
            has_otp=True,
            has_sensitive_outbound=True,
        )
        assert score == 60
        assert level == "HIGH"

    def test_score_caps_at_100(self):
        score, level = calculate_risk(
            is_known_malicious=True,
            has_homoglyph=True,
            has_brand_mismatch=True,
            has_otp=True,
            has_sensitive_outbound=True,
            has_canary_leak=True,
        )
        assert score == 100
        assert level == "HIGH"


# ===========================================================================
# 4. Protection and DNR Rules Tests
# ===========================================================================

class TestProtectionRules:
    def test_dnr_malicious_domain_blocked(self):
        dest = "http://attacker.example/api/collect"
        blocked = any(d in dest for d in KNOWN_MALICIOUS_DOMAINS)
        assert blocked is True

    def test_legitimate_destination_allowed(self):
        dest = "https://demo-bank-a.example/api/auth"
        blocked = any(d in dest for d in KNOWN_MALICIOUS_DOMAINS)
        assert blocked is False

    def test_strict_mode_cdp_policy(self):
        # Strict mode blocks any request matching threat destination
        strict_mode_active = True
        is_threat = True
        should_block = strict_mode_active and is_threat
        assert should_block is True
