"""Test battery for the audit log (S3).

Ported from the same author's nextcloud-access-broker tests/test_audit.py
(GPL-3.0-or-later) with the PIM field adaptations (account, resource,
backend) and the Tier-2 lifecycle event types (LIFECYCLE_EVENTS).

Goal contract requirements covered:

- Write-before-operate: the log entry is written and flushed BEFORE the
  caller proceeds. If the log write fails, the operation NEVER runs.
- Append-only: existing lines are never modified. Verified by checksum.
- Tamper evidence: each line carries the SHA256 of the previous line
  (hash chain). Truncation, reordering, and edits are detectable; the
  checkpoint sidecar catches tail loss.
- Record completeness: timestamp, account, backend, resource, operation,
  grant id, decision (lifecycle event / allowed / denied + reason),
  principal.
- No secrets: configured credentials must never appear in the log.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from access_broker_core import audit as audit_mod
from access_broker_core.audit import (
    LIFECYCLE_EVENTS,
    AuditLog,
    LogWriteError,
    verify_chain,
)

NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)


def make_log(tmp_path, **kwargs):
    return AuditLog(path=tmp_path / "audit.log", clock=lambda: NOW, **kwargs)


def record(log, **over):
    """Standard record call with the PIM-shaped defaults."""
    kwargs = {
        "account": "personal@example.com",
        "resource": "INBOX",
        "operation": "read",
        "grant_id": 7,
        "decision": "allowed",
        "reason": "ok",
    }
    kwargs.update(over)
    return log.record(**kwargs)


def lines_of(tmp_path, name="audit.log"):
    return (tmp_path / name).read_text().strip().splitlines()


# ------------------------------------------- write-before-operate


def test_write_then_operate_order(tmp_path):
    """The operation callback runs only after the log write succeeds."""
    log = make_log(tmp_path)
    ran = []
    record(log, then=lambda: ran.append(1))
    assert ran == [1]


def test_then_return_value_is_passed_through(tmp_path):
    """record() returns whatever the `then` callback returns."""
    log = make_log(tmp_path)
    sentinel = object()
    assert record(log, then=lambda: sentinel) is sentinel


def test_failed_log_write_refuses_operation(tmp_path):
    """The core security rule: if the log write fails, the operation is
    refused. The callback must NOT run, and an exception must propagate
    so the caller cannot mistake refusal for success."""
    log = make_log(tmp_path)
    ran = []
    with pytest.raises(LogWriteError):
        record(log, then=lambda: ran.append(1), _fail_inject=True)
    assert ran == []


def test_fail_inject_writes_nothing(tmp_path):
    """An injected write failure leaves no record and no chain advance."""
    log = make_log(tmp_path)
    record(log)
    with pytest.raises(LogWriteError):
        record(log, _fail_inject=True)
    assert len(lines_of(tmp_path)) == 1
    assert verify_chain(tmp_path / "audit.log").ok


def test_log_write_failure_on_real_disk_error(tmp_path):
    """Pointing the log at a directory: construction itself must fail
    closed (LogWriteError) - the broker must not start with an audit
    sink that cannot be written."""
    with pytest.raises(LogWriteError):
        AuditLog(path=tmp_path, clock=lambda: NOW)  # tmp_path IS a directory


def test_corrupt_tail_refuses_construction(tmp_path):
    """A log file whose last line is corrupt garbage: construction fails
    closed rather than silently extending a broken chain."""
    bad = tmp_path / "audit.log"
    bad.write_text("{not json at all\n")
    with pytest.raises(LogWriteError):
        AuditLog(path=bad, clock=lambda: NOW)


def test_corrupt_tail_missing_sha_key_refuses_construction(tmp_path):
    """A well-formed JSON tail without a sha256 field: fail closed."""
    bad = tmp_path / "audit.log"
    bad.write_text('{"foo": "bar"}\n')
    with pytest.raises(LogWriteError):
        AuditLog(path=bad, clock=lambda: NOW)


def test_record_write_oserror_refuses_operation(tmp_path, monkeypatch):
    """Simulate a mid-write OSError (disk full): operation refused."""
    import builtins

    log = make_log(tmp_path)
    ran = []
    real_open = builtins.open

    def flaky_open(*args, **kwargs):
        mode = args[1] if len(args) > 1 else kwargs.get("mode", "a")
        if "a" in mode and str(args[0]).endswith("audit.log"):
            raise OSError(28, "No space left on device")
        return real_open(*args, **kwargs)

    monkeypatch.setattr(builtins, "open", flaky_open)
    with pytest.raises(LogWriteError):
        record(log, then=lambda: ran.append(1))
    assert ran == []


def test_checkpoint_write_oserror_surfaces(tmp_path, monkeypatch):
    """The record is written but the checkpoint write fails: LogWriteError
    is raised so the operator notices; the chain itself stays valid."""
    import builtins

    log = make_log(tmp_path)
    ran = []
    real_open = builtins.open

    def flaky_open(*args, **kwargs):
        mode = args[1] if len(args) > 1 else kwargs.get("mode", "a")
        if "w" in mode and str(args[0]).endswith(".head"):
            raise OSError(5, "Input/output error")
        return real_open(*args, **kwargs)

    monkeypatch.setattr(builtins, "open", flaky_open)
    with pytest.raises(LogWriteError):
        record(log, then=lambda: ran.append(1))
    assert ran == []
    # the record itself was written
    assert len(lines_of(tmp_path)) == 1


# ------------------------------------------- record shape


def test_record_fields_complete(tmp_path):
    log = make_log(tmp_path)
    record(log, operation="write", grant_id=47, reason="approved by owner")
    record_d = json.loads(lines_of(tmp_path)[-1])
    assert record_d["timestamp"] == NOW.isoformat()
    assert record_d["account"] == "personal@example.com"
    assert record_d["resource"] == "INBOX"
    assert record_d["operation"] == "write"
    assert record_d["grant_id"] == 47
    assert record_d["decision"] == "allowed"
    assert record_d["reason"] == "approved by owner"
    assert "backend" not in record_d  # optional field: absent when not given


def test_record_with_backend_field_roundtrip(tmp_path):
    """The optional backend field is written and covered by the chain
    hash: the log verifies with it present."""
    log = make_log(tmp_path)
    record(log, backend="caldav", resource="Personal")
    result = verify_chain(tmp_path / "audit.log")
    assert result.ok, result.error
    record_d = json.loads(lines_of(tmp_path)[-1])
    assert record_d["backend"] == "caldav"
    assert record_d["resource"] == "Personal"


def test_backend_field_is_chained(tmp_path):
    """Editing the backend field of an existing line is detected."""
    log = make_log(tmp_path)
    record(log, backend="caldav", resource="Personal")
    lines = lines_of(tmp_path)
    record_d = json.loads(lines[0])
    record_d["backend"] = "msgraph"  # tampered
    (tmp_path / "audit.log").write_text(json.dumps(record_d, sort_keys=True) + "\n")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "hash mismatch" in (result.error or "")


def test_timestamp_is_injected_clock(tmp_path):
    """The clock is injected (same provider shape as grants/policy); two
    records from a ticking clock carry distinct timestamps."""
    tick = [NOW, NOW + timedelta(minutes=1)]
    log = AuditLog(path=tmp_path / "audit.log", clock=lambda: tick.pop(0))
    record(log, resource="a")
    record(log, resource="b")
    timestamps = [json.loads(ln)["timestamp"] for ln in lines_of(tmp_path)]
    assert timestamps == [NOW.isoformat(), (NOW + timedelta(minutes=1)).isoformat()]


def test_denied_operations_are_logged_too(tmp_path):
    """Refusals are audit events: who asked, what was refused, why."""
    log = make_log(tmp_path)
    record(log, grant_id=None, decision="denied", reason="path not covered by any active grant")
    record_d = json.loads(lines_of(tmp_path)[-1])
    assert record_d["decision"] == "denied"
    assert record_d["grant_id"] is None


def test_lifecycle_event_types_constant(tmp_path):
    """The Tier-2 lifecycle event set is exactly the D5 contract set."""
    assert frozenset(
        {"submitted", "approved", "rejected", "revoked", "expired_notice", "executed", "refused"}
    ) == LIFECYCLE_EVENTS


@pytest.mark.parametrize("event", sorted(LIFECYCLE_EVENTS))
def test_lifecycle_events_are_recordable(tmp_path, event):
    """Every Tier-2 lifecycle event type writes a verifiable entry with
    the event type in the decision field."""
    log = make_log(tmp_path)
    record(log, decision=event, reason=f"lifecycle {event}", grant_id=7)
    result = verify_chain(tmp_path / "audit.log")
    assert result.ok, result.error
    record_d = json.loads(lines_of(tmp_path)[-1])
    assert record_d["decision"] == event


def test_tier2_execution_intent_written_before_backend_call(tmp_path):
    """The Tier-2 pattern: the intent entry (decision 'executed') is
    durably written BEFORE the backend call, via the `then` callback."""
    log = make_log(tmp_path)
    calls = []

    def backend_call():
        # by the time the backend runs, the intent entry is already on disk
        assert verify_chain(tmp_path / "audit.log").ok
        lines = lines_of(tmp_path)
        assert json.loads(lines[-1])["decision"] == "executed"
        calls.append("backend")

    record(log, decision="executed", reason="grant 7 live", grant_id=7, then=backend_call)
    assert calls == ["backend"]


def test_secret_in_non_string_fields_ignored(tmp_path):
    """grant_id is an int; secrets checking must not choke on it."""
    log = make_log(tmp_path, secrets=["abc"])
    record(log, grant_id=123)
    assert verify_chain(tmp_path / "audit.log").ok


def test_secret_check_skips_non_string_values(tmp_path):
    """A non-string value in a checked field is skipped, not crashed on."""
    log = make_log(tmp_path)
    log._secrets = ["needle"]
    log._check_secrets("account", 123, None, "ok-resource", "allowed", "ok")  # no raise
    with pytest.raises(ValueError, match="secret"):
        log._check_secrets("account", "contains needle here")


def test_password_never_logged(tmp_path):
    """The audit log must never contain credentials. Feed a password-
    shaped string through every field and assert absence."""
    secret = "sup3r-secret-app-password"
    log = make_log(tmp_path, secrets=[secret])
    with pytest.raises(ValueError, match="secret"):
        record(
            log,
            account=f"a{secret}b",
            resource="resource-with-secret",
            operation="read",
            reason=f"why {secret}",
        )
    assert not (tmp_path / "audit.log").exists() or secret not in (tmp_path / "audit.log").read_text()


def test_secret_refusal_leaves_no_partial_record(tmp_path):
    """A secret-refused record leaves the chain untouched: a subsequent
    clean record chains from the previous head, and the log verifies."""
    secret = "hunter2-token"
    log = make_log(tmp_path, secrets=[secret])
    record(log, resource="clean-1")
    with pytest.raises(ValueError, match="secret"):
        record(log, resource=f"x{secret}y")
    record(log, resource="clean-2")
    result = verify_chain(tmp_path / "audit.log")
    assert result.ok, result.error
    assert len(lines_of(tmp_path)) == 2


def test_empty_secret_strings_ignored(tmp_path):
    """Empty strings in the configured secrets list are filtered out."""
    log = make_log(tmp_path, secrets=["", ""])
    record(log, resource="anything")  # no raise: no usable secret configured
    assert verify_chain(tmp_path / "audit.log").ok


def test_principal_field_roundtrip(tmp_path):
    """The audit record carries the principal (agent|transfer) and the
    chain hash covers it; a record without principal (legacy line) still
    verifies (backward compatible chain)."""
    assert "principal" in audit_mod._CHAINED_FIELDS
    log = make_log(tmp_path)
    record(log, principal="transfer", resource="a.tex")
    record(log, principal="agent", resource="b.tex")
    record(log, resource="c.tex")  # legacy call without principal: must still work
    result = verify_chain(tmp_path / "audit.log")
    assert result.ok, result.error
    records = [json.loads(ln) for ln in lines_of(tmp_path)]
    assert records[0]["principal"] == "transfer"
    assert records[1]["principal"] == "agent"
    assert "principal" not in records[2] or records[2]["principal"] is None


# ------------------------------------------- append-only + chain


def test_append_only_existing_lines_unmodified(tmp_path):
    log = make_log(tmp_path)
    for i in range(5):
        record(log, resource=f"f{i}")
    raw = (tmp_path / "audit.log").read_bytes()
    checksum_before = hashlib.sha256(raw).hexdigest()
    record(log, resource="another")
    raw_after = (tmp_path / "audit.log").read_bytes()
    assert raw_after.startswith(raw)  # strictly appended
    assert hashlib.sha256(raw).hexdigest() == checksum_before


def test_hash_chain_links_consecutive_lines(tmp_path):
    log = make_log(tmp_path)
    for i in range(3):
        record(log, resource=f"f{i}", backend="imap" if i % 2 else None)
    prev_hash = "0" * 64
    for line in lines_of(tmp_path):
        record_d = json.loads(line)
        assert record_d["prev_sha256"] == prev_hash
        payload = json.dumps(
            {k: record_d[k] for k in audit_mod._CHAINED_FIELDS if k in record_d},
            sort_keys=True,
        ).encode()
        prev_hash = hashlib.sha256(payload).hexdigest()
        assert record_d["sha256"] == prev_hash


def test_restart_continues_chain_from_last_head(tmp_path):
    """Second AuditLog instance on the same file continues the chain: the
    new record's prev_sha256 equals the last record's sha256."""
    log1 = make_log(tmp_path)
    record(log1, resource="f1")
    last_sha = json.loads(lines_of(tmp_path)[-1])["sha256"]
    log2 = make_log(tmp_path)
    record(log2, resource="f2")
    lines = lines_of(tmp_path)
    assert len(lines) == 2
    assert json.loads(lines[1])["prev_sha256"] == last_sha
    result = verify_chain(tmp_path / "audit.log")
    assert result.ok
    assert result.lines == 2


def test_empty_existing_log_file_construction_ok(tmp_path):
    """A zero-byte existing log file is treated as empty (genesis)."""
    (tmp_path / "audit.log").write_text("")
    log = make_log(tmp_path)
    record(log, resource="a")
    assert verify_chain(tmp_path / "audit.log").ok


def test_log_of_only_blank_lines_treated_as_empty(tmp_path):
    (tmp_path / "audit.log").write_text("\n \n")
    log = make_log(tmp_path)
    record(log, resource="a")
    assert verify_chain(tmp_path / "audit.log").ok


# ------------------------------------------- verify_chain


def test_verify_chain_ok_on_pristine_log(tmp_path):
    log = make_log(tmp_path)
    record(log, resource="f")
    assert verify_chain(tmp_path / "audit.log").ok


def test_verify_chain_empty_file_is_ok(tmp_path):
    (tmp_path / "audit.log").write_text("")
    assert verify_chain(tmp_path / "audit.log").ok


def test_verify_chain_missing_file_is_error(tmp_path):
    result = verify_chain(tmp_path / "nope.log")
    assert not result.ok
    assert result.lines == 0
    assert "no such file" in (result.error or "")


def test_verify_chain_detects_truncation(tmp_path):
    log = make_log(tmp_path)
    for i in range(4):
        record(log, resource=f"f{i}")
    assert verify_chain(tmp_path / "audit.log").ok
    # truncate one line
    lines = lines_of(tmp_path)
    (tmp_path / "audit.log").write_text("\n".join(lines[:-1]) + "\n")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert result.error


def test_verify_chain_missing_checkpoint_is_error(tmp_path):
    """A non-empty log whose .head sidecar is missing is a chain break:
    without the sidecar a truncated log would verify silently."""
    log = make_log(tmp_path)
    record(log, resource="f")
    head = tmp_path / "audit.log.head"
    assert head.exists()
    head.unlink()
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "checkpoint missing" in (result.error or "")


def test_verify_chain_fresh_log_without_sidecar_is_ok(tmp_path):
    """An empty log with no sidecar is a fresh file, not a truncation."""
    (tmp_path / "audit.log").write_text("")
    assert verify_chain(tmp_path / "audit.log").ok


def test_verify_chain_detects_reordering(tmp_path):
    log = make_log(tmp_path)
    for i in range(3):
        record(log, resource=f"f{i}")
    lines = lines_of(tmp_path)
    lines[0], lines[1] = lines[1], lines[0]
    (tmp_path / "audit.log").write_text("\n".join(lines) + "\n")
    assert not verify_chain(tmp_path / "audit.log").ok


def test_verify_chain_detects_content_edit(tmp_path):
    log = make_log(tmp_path)
    for i in range(3):
        record(log, resource=f"f{i}")
    lines = lines_of(tmp_path)
    record_d = json.loads(lines[1])
    record_d["resource"] = "tampered"
    lines[1] = json.dumps(record_d, sort_keys=True)
    (tmp_path / "audit.log").write_text("\n".join(lines) + "\n")
    assert not verify_chain(tmp_path / "audit.log").ok


def test_verify_chain_detects_deleted_first_line(tmp_path):
    """Deleting the FIRST line is also a chain break: line 2's prev no
    longer matches genesis."""
    log = make_log(tmp_path)
    for i in range(3):
        record(log, resource=f"f{i}")
    lines = lines_of(tmp_path)
    (tmp_path / "audit.log").write_text("\n".join(lines[1:]) + "\n")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "prev mismatch" in (result.error or "")


def test_invalid_json_line_detected(tmp_path):
    """A log line that is not valid JSON is named and refused."""
    log = make_log(tmp_path)
    record(log, resource="f")
    with open(tmp_path / "audit.log", "a") as f:
        f.write("this is not json\n")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "not valid JSON" in (result.error or "")


def test_prev_mismatch_detected_on_handcrafted_break(tmp_path):
    """Handcraft a chain where line 2's prev_sha256 does not match line 1's
    sha256 but line 2's own hash is internally consistent - the pure
    prev-mismatch branch (no line-2 hash check fires first)."""
    log = make_log(tmp_path)
    record(log, resource="f1")
    lines = lines_of(tmp_path)
    # a second record whose own hash is right but prev is wrong
    entry2 = {
        "timestamp": NOW.isoformat(),
        "account": "personal@example.com",
        "resource": "f2",
        "operation": "read",
        "grant_id": 7,
        "decision": "allowed",
        "reason": "ok",
    }
    r2 = dict(entry2)
    r2["prev_sha256"] = "b" * 64  # wrong on purpose
    r2["sha256"] = hashlib.sha256(audit_mod._chain_payload(entry2).encode()).hexdigest()
    (tmp_path / "audit.log").write_text(lines[0] + "\n" + json.dumps(r2, sort_keys=True) + "\n")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "prev mismatch" in (result.error or "")


def test_verify_chain_unreadable_log(tmp_path):
    """A directory in place of the log file: read fails, error returned."""
    (tmp_path / "subdir").mkdir()
    result = verify_chain(tmp_path / "subdir")
    assert not result.ok


# ------------------------------------------- checkpoint sidecar


def test_checkpoint_tampering_detected(tmp_path):
    """Editing the checkpoint head hash itself is detected by mismatch."""
    log = make_log(tmp_path)
    for i in range(2):
        record(log, resource=f"f{i}")
    head_path = tmp_path / "audit.log.head"
    head = json.loads(head_path.read_text())
    head["sha256"] = "f" * 64
    head_path.write_text(json.dumps(head, sort_keys=True) + "\n")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "checkpoint mismatch" in result.error


def test_checkpoint_line_count_tampering_detected(tmp_path):
    log = make_log(tmp_path)
    for i in range(2):
        record(log, resource=f"f{i}")
    head_path = tmp_path / "audit.log.head"
    head = json.loads(head_path.read_text())
    head["lines"] = 99
    head_path.write_text(json.dumps(head, sort_keys=True) + "\n")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "truncated" in result.error


def test_corrupt_checkpoint_detected(tmp_path):
    log = make_log(tmp_path)
    record(log, resource="f")
    (tmp_path / "audit.log.head").write_text("{garbage")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "checkpoint unreadable" in (result.error or "")


def test_missing_checkpoint_after_records_is_error(tmp_path):
    """A non-empty log whose checkpoint sidecar is missing is a chain
    break: without the sidecar a truncated log verifies silently — the
    exact case the checkpoint mechanism exists to catch (Stage 8
    supervisory finding; supersedes the earlier by-chain-alone
    behavior)."""
    log = make_log(tmp_path)
    record(log, resource="f")
    (tmp_path / "audit.log.head").unlink()
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "checkpoint missing" in (result.error or "")


def test_checkpoint_tracks_line_count(tmp_path):
    log = make_log(tmp_path)
    for i in range(3):
        record(log, resource=f"f{i}")
    head = json.loads((tmp_path / "audit.log.head").read_text())
    assert head["lines"] == 3
    assert head["sha256"] == json.loads(lines_of(tmp_path)[-1])["sha256"]


# ------------------------------------------- concurrent append interleaving
# (single-writer process: records from one instance and across instances
# must never interleave partial lines - fsync'd whole-line appends)


def test_sequential_appends_produce_whole_lines(tmp_path):
    """Every line in a heavily appended log parses as one JSON object:
    no torn writes within the single writer."""
    log = make_log(tmp_path)
    for i in range(50):
        record(log, resource=f"f{i}", grant_id=i)
    lines = lines_of(tmp_path)
    assert len(lines) == 50
    for line in lines:
        record_d = json.loads(line)  # must not raise
        assert record_d["resource"].startswith("f")
    assert verify_chain(tmp_path / "audit.log").ok


def test_two_interleaved_instances_single_threaded(tmp_path):
    """Two AuditLog instances on the same file, used round-robin, still
    produce a verifiable chain when the second re-reads the head each
    construction - the single-writer-process discipline documented in
    05_concurrency (no two live writers)."""
    log1 = make_log(tmp_path)
    record(log1, resource="a")
    log2 = make_log(tmp_path)
    record(log2, resource="b")
    log3 = make_log(tmp_path)
    record(log3, resource="c")
    assert verify_chain(tmp_path / "audit.log").ok
    assert verify_chain(tmp_path / "audit.log").lines == 3


# ------------------------------------------- rotation-free growth


def test_no_rotation_growth_unbounded(tmp_path):
    """The log grows without rotation: 200 records, all present, chain
    verified end to end (rotation-free growth cap behavior: none)."""
    log = make_log(tmp_path)
    for i in range(200):
        record(log, resource=f"f{i}")
    assert verify_chain(tmp_path / "audit.log").lines == 200


# ------------------------------------------- screen field (S2, design note 2026-10-01)


def test_screen_field_written_when_declared(tmp_path):
    """A declared screen verdict rides the record and the chain."""
    log = make_log(tmp_path)
    record(log, screen="refused")
    lines = lines_of(tmp_path)
    rec = json.loads(lines[0])
    assert rec["screen"] == "refused"
    assert verify_chain(tmp_path / "audit.log").ok


def test_screen_field_absent_when_none(tmp_path):
    """None means no declaration: the field is absent (legacy shape)."""
    log = make_log(tmp_path)
    record(log)
    rec = json.loads(lines_of(tmp_path)[0])
    assert "screen" not in rec
    assert verify_chain(tmp_path / "audit.log").ok


@pytest.mark.parametrize(
    "value",
    ["clear", "flagged", "refused", "unscreened", "model_unavailable", "screen_error"],
)
def test_screen_vocabulary_accepted(tmp_path, value):
    log = make_log(tmp_path)
    record(log, screen=value)
    assert json.loads(lines_of(tmp_path)[0])["screen"] == value
    assert verify_chain(tmp_path / "audit.log").ok


def test_screen_unknown_value_refused_before_write(tmp_path):
    """Fail-closed vocabulary gate: an unknown verdict is refused and
    leaves NO partial record (the entry is built after the checks)."""
    log = make_log(tmp_path)
    with pytest.raises(ValueError, match="screen"):
        record(log, screen="probably-fine")
    assert not (tmp_path / "audit.log").exists()


def test_screen_field_is_chained(tmp_path):
    """Editing the screen field of an existing line is detected."""
    log = make_log(tmp_path)
    record(log, screen="clear")
    rec = json.loads(lines_of(tmp_path)[0])
    rec["screen"] = "refused"  # tampered
    (tmp_path / "audit.log").write_text(json.dumps(rec, sort_keys=True) + "\n")
    result = verify_chain(tmp_path / "audit.log")
    assert not result.ok
    assert "hash mismatch" in (result.error or "")


def test_legacy_lines_without_screen_verify(tmp_path):
    """A pre-screening line followed by a screened line: both verify."""
    log = make_log(tmp_path)
    record(log, resource="legacy")
    record(log, resource="screened", screen="flagged")
    assert verify_chain(tmp_path / "audit.log").lines == 2


def test_screen_secret_check_still_applies(tmp_path):
    """A record VALUE containing a configured secret is refused even
    when a screen verdict is declared alongside it (the screen field
    does not bypass the secret-scrubbing gate)."""
    log = AuditLog(
        path=tmp_path / "audit.log", clock=lambda: NOW, secrets=["hunter2"]
    )
    with pytest.raises(ValueError, match="secret"):
        record(log, reason="password is hunter2", screen="clear")
