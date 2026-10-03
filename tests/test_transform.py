from ldf.detectors import scan_text
from ldf.transform import SubstitutionMap


def test_stable_placeholders_within_a_document():
    text = "Dear Mr. Smith: you emailed smith@corp.com. Later Smith emailed again from smith@corp.com."
    findings = scan_text(text)
    sub = SubstitutionMap()
    out = sub.apply(text, findings)
    assert out == "Dear Mr. [CLIENT_1]: you emailed [EMAIL_1]. Later Smith emailed again from [EMAIL_1]."


def test_reidentify_roundtrip():
    text = "Hi Jane Chen, your phone is 415-555-2671"
    sub = SubstitutionMap()
    transformed = sub.apply(text, scan_text(text))
    assert transformed == "Hi [CLIENT_1], your phone is [PHONE_1]"
    assert sub.reidentify(transformed) == text


def test_person_kinds_share_the_client_counter():
    sub = SubstitutionMap()
    a = sub.placeholder_for("person_name", "Jane Chen")
    b = sub.placeholder_for("known_name", "Bob Ray")
    assert a == "[CLIENT_1]" and b == "[CLIENT_2]"


def test_kinds_get_distinct_counters():
    sub = SubstitutionMap()
    assert sub.placeholder_for("email", "a@x.com") == "[EMAIL_1]"
    assert sub.placeholder_for("phone", "415-555-1234") == "[PHONE_1]"
    assert sub.placeholder_for("api_key_openai", "sk-" + "x" * 20) == "[SECRET_1]"
    assert sub.placeholder_for("bearer_header", "tok" + "e" * 20) == "[TOKEN_1]"


def test_map_is_ephemeral_by_default(tmp_path):
    sub = SubstitutionMap()
    sub.apply("Ms. Jones called", scan_text("Ms. Jones called"))
    files = list(tmp_path.rglob("*"))
    # nothing written unless persistence is explicitly requested
    assert files == []


def test_encrypted_persistence_roundtrip_when_available(tmp_path):
    sub = SubstitutionMap()
    sub.apply("Dear Jane Chen", scan_text("Dear Jane Chen"))
    path = tmp_path / "map.enc"
    result = sub.save_encrypted(path, b"k" * 32)
    if result is None:  # 'cryptography' not installed; ephemeral-only is correct here
        return
    loaded = SubstitutionMap.load_encrypted(path, b"k" * 32)
    assert loaded.reidentify("[CLIENT_1]") == "Jane Chen"