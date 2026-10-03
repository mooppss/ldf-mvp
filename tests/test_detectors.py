from ldf.detectors import scan_text


def rule_ids(text, **kw):
    return [f.rule_id for f in scan_text(text, **kw)]


def test_openai_and_anthropic_keys_dedupe_to_specific():
    text = "key is sk-ant-api03-" + "x" * 24
    ids = rule_ids(text)
    assert "R-SEC-002" in ids
    assert "R-SEC-001" not in ids  # contained within the more specific finding


def test_aws_key():
    assert "R-SEC-004" in rule_ids("aws_key = AKIAIOSFODNN7EXAMPLE")


def test_jwt():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert "R-SEC-007" in rule_ids(f"token: {jwt}")


def test_pem_header():
    assert "R-SEC-009" in rule_ids("-----BEGIN RSA PRIVATE KEY-----")


def test_credential_assignment_captures_value():
    findings = scan_text("My password is hunter2secret")
    f = [f for f in findings if f.rule_id == "R-SEC-010"][0]
    assert f.value == "hunter2secret"


def test_bearer_captures_token_value():
    findings = scan_text("Authorization: Bearer abc123def456ghi789jklm=")
    f = [f for f in findings if f.rule_id == "R-SEC-008"][0]
    assert f.value == "abc123def456ghi789jklm="


def test_email():
    findings = scan_text("write to jane@example.com today")
    assert any(f.rule_id == "R-PII-001" and f.value == "jane@example.com" for f in findings)


def test_card_luhn_positive_and_negative():
    assert any(f.rule_id == "R-PII-002" for f in scan_text("card 4111 1111 1111 1111"))
    assert not any(f.rule_id == "R-PII-002" for f in scan_text("card 4111 1111 1111 1112"))
    # amex 4-6-5 grouping
    assert any(f.rule_id == "R-PII-002" for f in scan_text("amex 3782 822463 10005"))


def test_ssn_valid_and_invalid_area():
    assert any(f.rule_id == "R-PII-003" for f in scan_text("ssn 123-45-6789"))
    assert not any(f.rule_id == "R-PII-003" for f in scan_text("ssn 900-45-6789"))
    assert not any(f.rule_id == "R-PII-003" for f in scan_text("ssn 000-45-6789"))


def test_phone_formats():
    for sample in ("call 415-555-2671", "call +1 (415) 555-2671", "call 415.555.2671"):
        assert any(f.rule_id == "R-PII-004" and f.value.endswith("2671") for f in scan_text(sample))


def test_context_cued_names():
    findings = scan_text("Dear Jane Chen, please find the invoice.")
    name = [f for f in findings if f.rule_id == "R-PII-005"][0]
    assert name.value == "Jane Chen"
    assert scan_text("Mr. Smith called today.")[0].value == "Smith"


def test_name_precision_no_cue_no_match():
    assert rule_ids("The report is ready for review.") == []
    assert not any(f.rule_id == "R-PII-005" for f in scan_text("Jane Chen's email"))


def test_known_names_from_policy():
    findings = scan_text("Acme Corp signed with Acme Corp", known_names=["Acme Corp"], skip_names=[])
    assert [f.rule_id for f in findings].count("R-PII-006") == 2


def test_skip_names():
    findings = scan_text("Dear Jane Chen,", known_names=["Jane Chen"], skip_names=["Jane Chen"])
    assert findings == []


def test_no_false_positive_on_ordinary_biz_text():
    assert rule_ids("The invoice totals 4040 dollars and ships 2026. Q1 margins were 12%.") == []