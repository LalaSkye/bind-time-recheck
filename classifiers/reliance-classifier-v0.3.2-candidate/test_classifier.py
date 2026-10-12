#!/usr/bin/env python3
"""Classifier-only tests for v0.3.2.

Synthetic classifier inputs are labelled as such. They are not new
control observations. No original control or compiled cache is imported.
"""
import json
import sys
from pathlib import Path
from contextlib import redirect_stdout
from io import StringIO
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import classify as classifier_module
from classify import (
    classify,
    classify_detail,
    execution_eligible,
    invalid_authorisation_established,
    binding_evidence,
    withdrawal_before_crossing,
)

HERE = Path(__file__).resolve().parent
RECEIPT = json.loads((HERE / "supporting-receipt-run1.json").read_text())
CASES = {c["case"]: c for c in RECEIPT["cases"]}


def assert_eq(got, expected, label):
    if got != expected:
        raise AssertionError(f"{label}: got {got!r}, expected {expected!r}")


def main():
    results = []

    # Preserved observations. Regression expectations, not forced verdicts.
    assert_eq(classify(CASES["A"]), "NOT_CONTRADICTED_BY_THIS_OBSERVATION", "A")
    results.append("A: NOT_CONTRADICTED_BY_THIS_OBSERVATION")
    assert_eq(classify(CASES["M"]), "CLAIM_CONTRADICTED", "M")
    results.append("M: CLAIM_CONTRADICTED")
    assert_eq(classify(CASES["B"]), "NOT_CONTRADICTED_BY_THIS_OBSERVATION", "B")
    results.append("B: NOT_CONTRADICTED_BY_THIS_OBSERVATION")

    # R1: matching binding evidence on a preserved case.
    ok, reason = binding_evidence(CASES["A"])
    assert_eq(ok, True, "A binding ok")
    results.append(f"R1 matching binding evidence (A): {reason}")

    # Existing: missing decision evidence.
    synthetic_missing_reason = json.loads(json.dumps(CASES["M"]))
    synthetic_missing_reason["observed"].pop("bind_reason", None)
    assert_eq(execution_eligible(synthetic_missing_reason), None, "missing reason eligible")
    assert_eq(classify(synthetic_missing_reason), "UNRESOLVED", "missing reason")
    results.append("synthetic missing bind_reason: UNRESOLVED")

    # Existing: withdrawal acknowledged but no continuing-effect evidence.
    synthetic_no_effect = json.loads(json.dumps(CASES["A"]))
    synthetic_no_effect["observed"]["events"] = [
        e for e in synthetic_no_effect["observed"]["events"]
        if e.get("event") != "live_read" or e.get("accepted") is not False
    ]
    assert_eq(invalid_authorisation_established(synthetic_no_effect), None, "no effect invalid")
    assert_eq(classify(synthetic_no_effect), "UNRESOLVED", "no effect")
    results.append("synthetic withdrawal without continuing-effect evidence: UNRESOLVED")

    # R2: written with zero writer entries is UNRESOLVED, not CLAIM_CONTRADICTED.
    synthetic_written_zero = json.loads(json.dumps(CASES["A"]))
    synthetic_written_zero["observed"]["bind_reason"] = "written"
    synthetic_written_zero["observed"]["writer_entry_count"] = 0
    assert_eq(classify(synthetic_written_zero), "UNRESOLVED", "written/zero")
    assert_eq(
        "writer_entry_count=0" in classify_detail(synthetic_written_zero)["reason"],
        True,
        "written/zero reason",
    )
    results.append("R2 synthetic bind_reason=written with writer_entry_count=0: UNRESOLVED")

    # R2: recorded refusal together with writer entry is UNRESOLVED.
    synthetic_refusal_entry = json.loads(json.dumps(CASES["A"]))
    synthetic_refusal_entry["observed"]["bind_reason"] = "authority_not_current"
    synthetic_refusal_entry["observed"]["writer_entry_count"] = 1
    assert_eq(classify(synthetic_refusal_entry), "UNRESOLVED", "refusal/entry")
    results.append("R2 synthetic refusal with writer_entry_count=1: UNRESOLVED")

    # Existing: no withdrawal, missing freshness must not invent invalid auth.
    synthetic_no_wd = json.loads(json.dumps(CASES["B"]))
    synthetic_no_wd["observed"]["bind_fresh_read"] = False
    synthetic_no_wd["configuration"]["trust_prior_used"] = False
    assert_eq(invalid_authorisation_established(synthetic_no_wd), False, "no wd invalid")
    assert_eq(classify(synthetic_no_wd), "NOT_CONTRADICTED_BY_THIS_OBSERVATION", "no wd")
    results.append("synthetic no withdrawal + missing freshness: NOT_CONTRADICTED")

    # R1: missing instruction digest.
    synthetic_missing_digest = json.loads(json.dumps(CASES["M"]))
    synthetic_missing_digest["observed"].pop("bind_packet_sha256_observed", None)
    assert_eq(classify(synthetic_missing_digest), "UNRESOLVED", "missing digest")
    results.append("R1 synthetic missing bind_packet_sha256_observed: UNRESOLVED")

    # R1: mismatched instruction digests.
    synthetic_mismatch_digest = json.loads(json.dumps(CASES["M"]))
    synthetic_mismatch_digest["observed"]["bind_packet_sha256_observed"] = "0" * 64
    assert_eq(classify(synthetic_mismatch_digest), "UNRESOLVED", "mismatch digest")
    results.append("R1 synthetic mismatched instruction digest: UNRESOLVED")

    # R1: missing ticket evidence.
    synthetic_missing_ticket = json.loads(json.dumps(CASES["M"]))
    synthetic_missing_ticket["configuration"].pop("ticket", None)
    assert_eq(classify(synthetic_missing_ticket), "UNRESOLVED", "missing ticket")
    results.append("R1 synthetic missing configuration.ticket: UNRESOLVED")

    # R1: mismatched ticket evidence.
    synthetic_mismatch_ticket = json.loads(json.dumps(CASES["M"]))
    synthetic_mismatch_ticket["configuration"]["issuer_seed_request"]["ticket"] = "other-ticket"
    assert_eq(classify(synthetic_mismatch_ticket), "UNRESOLVED", "mismatch ticket")
    results.append("R1 synthetic mismatched ticket fields: UNRESOLVED")

    # R1: malformed binding value.
    synthetic_malformed = json.loads(json.dumps(CASES["M"]))
    synthetic_malformed["configuration"]["driver_supplied_packet_sha256"] = "not-a-digest"
    assert_eq(classify(synthetic_malformed), "UNRESOLVED", "malformed digest")
    results.append("R1 synthetic malformed instruction digest: UNRESOLVED")

    # R1: equally missing digests must not pass as a match.
    synthetic_all_missing = json.loads(json.dumps(CASES["M"]))
    synthetic_all_missing["configuration"].pop("driver_supplied_packet_sha256", None)
    synthetic_all_missing["configuration"]["issuer_seed_request"].pop("packet_sha256", None)
    synthetic_all_missing["observed"].pop("check_packet_sha256_observed", None)
    synthetic_all_missing["observed"].pop("bind_packet_sha256_observed", None)
    assert_eq(classify(synthetic_all_missing), "UNRESOLVED", "equally missing")
    results.append("R1 synthetic equally missing instruction digests: UNRESOLVED")

    def move_ack(case, after_event):
        """Synthetic: move the matching-ticket acknowledgement after a named event."""
        events = case["observed"]["events"]
        ticket = case["configuration"]["ticket"]
        ack = None
        rest = []
        for ev in events:
            if (
                ack is None
                and ev.get("event") == "issuer_revocation_acknowledged"
                and ev.get("revoked") == ticket
            ):
                ack = ev
            else:
                rest.append(ev)
        placed = False
        ordered = []
        for ev in rest:
            ordered.append(ev)
            if not placed and ev.get("event") == after_event:
                ordered.append(ack)
                placed = True
        if not placed:
            ordered.append(ack)
        case["observed"]["events"] = ordered
        return case

    # R3: preserved M order is established.
    status, reason = withdrawal_before_crossing(CASES["M"])
    assert_eq(status, "established", "M order")
    results.append(f"R3 preserved M order: {reason}")

    # R3: acknowledgement moved after write_completed must not stay contradicted.
    synthetic_after_complete = move_ack(json.loads(json.dumps(CASES["M"])), "write_completed")
    assert_eq(classify(synthetic_after_complete), "UNRESOLVED", "ack after complete")
    results.append("R3 synthetic acknowledgement after write_completed: UNRESOLVED")

    # R3: acknowledgement after writer_entered but before write_completed.
    synthetic_after_entry = move_ack(json.loads(json.dumps(CASES["M"])), "writer_entered")
    assert_eq(classify(synthetic_after_entry), "UNRESOLVED", "ack after entry")
    results.append("R3 synthetic acknowledgement after writer_entered: UNRESOLVED")

    # R3: M-derived missing the acknowledgement.
    synthetic_missing_ack = json.loads(json.dumps(CASES["M"]))
    synthetic_missing_ack["observed"]["events"] = [
        ev for ev in synthetic_missing_ack["observed"]["events"]
        if ev.get("event") != "issuer_revocation_acknowledged"
    ]
    assert_eq(classify(synthetic_missing_ack), "UNRESOLVED", "missing ack")
    results.append("R3 synthetic M missing acknowledgement: UNRESOLVED")

    # R3: M-derived missing the ordering witness.
    synthetic_missing_witness = json.loads(json.dumps(CASES["M"]))
    synthetic_missing_witness["observed"]["events"] = [
        ev for ev in synthetic_missing_witness["observed"]["events"]
        if ev.get("event") != "writer_entered"
    ]
    assert_eq(classify(synthetic_missing_witness), "UNRESOLVED", "missing witness")
    results.append("R3 synthetic M missing writer_entered: UNRESOLVED")

    # R3: acknowledgement for another ticket cannot establish the order.
    synthetic_other_ticket = json.loads(json.dumps(CASES["M"]))
    for ev in synthetic_other_ticket["observed"]["events"]:
        if ev.get("event") == "issuer_revocation_acknowledged":
            ev["revoked"] = "other-ticket"
    assert_eq(classify(synthetic_other_ticket), "UNRESOLVED", "other ticket")
    results.append("R3 synthetic acknowledgement for another ticket: UNRESOLVED")

    ticket = CASES["B"]["configuration"]["ticket"]

    # R3 fresh path: exact B counterexample. Authorised write, then a
    # matching acknowledgement and refusing read after write_completed.
    synthetic_b_after = json.loads(json.dumps(CASES["B"]))
    synthetic_b_after["observed"]["events"].append(
        {"event": "issuer_revocation_acknowledged", "revoked": ticket}
    )
    synthetic_b_after["observed"]["events"].append(
        {"event": "live_read", "accepted": False, "revoked": [ticket]}
    )
    got = classify(synthetic_b_after)
    assert_eq(got, "UNRESOLVED", "B after write")
    results.append(
        "R3 fresh-path B-derived ack and refusal after write_completed: "
        f"expected UNRESOLVED, actual {got}"
    )

    # R3 fresh path: acknowledgement after writer_entered, before
    # write_completed, then a refusing read.
    synthetic_b_mid = json.loads(json.dumps(CASES["B"]))
    events = synthetic_b_mid["observed"]["events"]
    inserted = []
    for ev in events:
        inserted.append(ev)
        if ev.get("event") == "writer_entered":
            inserted.append(
                {"event": "issuer_revocation_acknowledged", "revoked": ticket}
            )
    inserted.append({"event": "live_read", "accepted": False, "revoked": [ticket]})
    synthetic_b_mid["observed"]["events"] = inserted
    got = classify(synthetic_b_mid)
    assert_eq(got, "UNRESOLVED", "B ack between entry and complete")
    results.append(
        "R3 fresh-path ack after writer_entered before write_completed: "
        f"expected UNRESOLVED, actual {got}"
    )

    # R3 fresh path: matching ack present, writer_entered missing.
    synthetic_b_ambiguous = json.loads(json.dumps(CASES["B"]))
    synthetic_b_ambiguous["observed"]["events"] = [
        ev for ev in synthetic_b_ambiguous["observed"]["events"]
        if ev.get("event") != "writer_entered"
    ]
    synthetic_b_ambiguous["observed"]["events"].append(
        {"event": "issuer_revocation_acknowledged", "revoked": ticket}
    )
    synthetic_b_ambiguous["observed"]["events"].append(
        {"event": "live_read", "accepted": False, "revoked": [ticket]}
    )
    got = classify(synthetic_b_ambiguous)
    assert_eq(got, "UNRESOLVED", "B missing witness")
    results.append(
        "R3 fresh-path missing writer_entered with later withdrawal: "
        f"expected UNRESOLVED, actual {got}"
    )

    # R3 fresh path: another ticket's acknowledgement cannot satisfy the match.
    synthetic_b_other = json.loads(json.dumps(CASES["B"]))
    synthetic_b_other["observed"]["events"].append(
        {"event": "issuer_revocation_acknowledged", "revoked": "other-ticket"}
    )
    synthetic_b_other["observed"]["events"].append(
        {"event": "live_read", "accepted": False, "revoked": [ticket]}
    )
    got = classify(synthetic_b_other)
    assert_eq(got, "NOT_CONTRADICTED_BY_THIS_OBSERVATION", "B other ticket")
    results.append(
        "R3 fresh-path acknowledgement for another ticket: "
        f"expected NOT_CONTRADICTED_BY_THIS_OBSERVATION, actual {got}"
    )

    # Reviewer counterexample 1: the closing summary must follow the verdict.
    mutated_receipt = json.loads(json.dumps(RECEIPT))
    for case in mutated_receipt["cases"]:
        if case["case"] == "M":
            case["observed"].pop("bind_packet_sha256_observed", None)
    with TemporaryDirectory() as td:
        receipt_path = Path(td) / "mutated-receipt.json"
        receipt_path.write_text(json.dumps(mutated_receipt))
        capture = StringIO()
        with patch.object(classifier_module, "RECEIPT", receipt_path):
            with redirect_stdout(capture):
                classifier_module.main()
        output = capture.getvalue()
    summary = output.split("Summary (derived from the classifications above):\n", 1)
    assert_eq(len(summary), 2, "derived summary present")
    assert_eq("Case M: UNRESOLVED" in summary[1], True, "missing digest M summary")
    assert_eq("Case M: CLAIM_CONTRADICTED" in summary[1], False, "no fixed contradicted M")
    results.append("review repair: missing M digest produces UNRESOLVED in final summary")

    # Reviewer counterexample 2: count must equal the observed entry events.
    synthetic_count_two = json.loads(json.dumps(CASES["M"]))
    synthetic_count_two["observed"]["writer_entry_count"] = 2
    count_detail = classify_detail(synthetic_count_two)
    assert_eq(count_detail["verdict"], "UNRESOLVED", "two counted vs one entry")
    assert_eq("writer_entry_count=2" in count_detail["reason"], True, "count mismatch reason")
    results.append("review repair: M count=2 with one writer_entered is UNRESOLVED")

    out = HERE / "classifier-output.txt"
    text = "\n".join(results) + "\n"
    out.write_text(text)
    print(text)
    print("All classifier-only checks passed.")


if __name__ == "__main__":
    main()
