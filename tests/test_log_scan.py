import pathlib

from nextguard import log_scan as ls

SAMPLES = pathlib.Path(__file__).resolve().parents[1] / "detection" / "samples"


def test_json_attack_detected():
    dets = ls.scan_file(SAMPLES / "access-json.log")
    # lines 2, 3 are high-confidence attacks; line 5 is a paired-id internal subrequest
    attacks = [d for d in dets if not d.has_valid_id_pairing]
    assert len(attacks) == 2
    assert all(d.confidence == "high" for d in attacks)
    assert all(d.repeated_known_token for d in attacks)


def test_prose_mention_not_flagged():
    # line 4 mentions the header only inside a string value, not as a header key
    dets = ls.scan_file(SAMPLES / "access-json.log")
    assert not any(d.line_no == 4 for d in dets)


def test_paired_id_recognized():
    dets = ls.scan_file(SAMPLES / "access-json.log")
    paired = [d for d in dets if d.has_valid_id_pairing]
    assert len(paired) == 1
    assert paired[0].header_value == "middleware"


def test_header_dump_format():
    dets = ls.scan_file(SAMPLES / "header-dump.log")
    assert len(dets) == 1
    assert dets[0].confidence == "high"
    assert "pages/_middleware" in dets[0].header_value


def test_benign_log_clean():
    dets = ls.scan_file(SAMPLES / "benign.log")
    assert dets == []


def test_bare_header_is_medium():
    line = '{"headers":{"x-middleware-subrequest":"middleware"}}'
    det = ls.scan_line(line, 1)
    assert det is not None
    assert det.confidence == "medium"
    assert not det.repeated_known_token


def test_depth_trigger_unknown_token_is_high():
    # five identical arbitrary tokens still trips the recursion-depth skip
    line = '{"headers":{"x-middleware-subrequest":"x:x:x:x:x"}}'
    det = ls.scan_line(line, 1)
    assert det.confidence == "high"


def test_empty_and_unrelated_lines():
    assert ls.scan_line("", 1) is None
    assert ls.scan_line('{"headers":{"user-agent":"curl"}}', 1) is None
