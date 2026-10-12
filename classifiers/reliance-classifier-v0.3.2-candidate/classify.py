#!/usr/bin/env python3
"""Local classifier for the reliance-after-change specimen (v0.3.2 repair).

Applies an explicit classification rule to preserved observations.
Does not rerun the original first-build. Synthetic only.

v0.3.2 repair (R3 finished across both paths; R1 and R2 preserved):
Every withdrawal-based CLAIM_CONTRADICTED requires source-grounded evidence
that effective withdrawal for the same ticket and bound instruction preceded
the eligibility decision. This does not depend on trust_prior_used.
A withdrawal or refusing read after a completed write cannot establish
invalid authorisation at the earlier decision. A genuine refusal (A) does
not need a writer-entry witness. A genuine no-withdrawal reference (B)
does not need a withdrawal event.
"""
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
RECEIPT = HERE / "supporting-receipt-run1.json"

REFUSAL_REASONS = ("authority_not_current", "binding_mismatch")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")

# Field paths that establish the ticket. Both must be present and equal.
TICKET_PATHS = (
    ("configuration", "ticket"),
    ("configuration", "issuer_seed_request", "ticket"),
)

# Field paths that establish the bound instruction (packet digest).
# The binding record and both observed digests are required.
DIGEST_PATHS = (
    ("configuration", "driver_supplied_packet_sha256"),
    ("configuration", "issuer_seed_request", "packet_sha256"),
    ("observed", "check_packet_sha256_observed"),
    ("observed", "bind_packet_sha256_observed"),
)


def _get_path(obj, path):
    cur = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None, False
        cur = cur[key]
    return cur, True


def _path_label(path):
    return ".".join(path)


def binding_evidence(case):
    """Check ticket and bound-instruction evidence against the receipt.

    Returns (True, reason) only when every required value is present,
    well-formed and consistent. Equally missing values do not match.
    """
    if not isinstance(case, dict):
        return False, "binding evidence missing: case is not an object"

    tickets = []
    for path in TICKET_PATHS:
        value, present = _get_path(case, path)
        label = _path_label(path)
        if not present or value is None or value == "":
            return False, f"binding evidence missing: {label}"
        if not isinstance(value, str):
            return False, f"binding evidence malformed: {label} is not a string"
        tickets.append((label, value))
    ticket_values = {value for _, value in tickets}
    if len(ticket_values) != 1:
        return False, "binding evidence conflict: ticket fields disagree"

    digests = []
    for path in DIGEST_PATHS:
        value, present = _get_path(case, path)
        label = _path_label(path)
        if not present or value is None or value == "":
            return False, f"binding evidence missing: {label}"
        if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
            return False, f"binding evidence malformed: {label} is not 64 lowercase hex"
        digests.append((label, value))
    digest_values = {value for _, value in digests}
    if len(digest_values) != 1:
        return False, "binding evidence conflict: instruction digests disagree"

    return True, "ticket and bound instruction present, well-formed and consistent"


def observation_consistency(case):
    """Check bind_reason against writer entry. Do not prefer one field.

    Eligibility is bind_reason. Writer entry is writer_entry_count.
    Completed writing is a write_completed event. They are not interchangeable.
    Zero writer entries alone do not establish refusal.
    """
    observed = case.get("observed") if isinstance(case, dict) else None
    if not isinstance(observed, dict):
        return False, "observation evidence missing: observed"

    reason = observed.get("bind_reason")
    if "writer_entry_count" not in observed or observed.get("writer_entry_count") is None:
        return False, "observation evidence missing: observed.writer_entry_count"
    count = observed.get("writer_entry_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return False, "observation evidence malformed: observed.writer_entry_count"

    events = observed.get("events", [])
    if not isinstance(events, list):
        return False, "observation evidence malformed: observed.events"
    completed = any(
        isinstance(ev, dict) and ev.get("event") == "write_completed" for ev in events
    )

    if reason == "written" and count == 0:
        return False, "observation conflict: bind_reason=written with writer_entry_count=0"
    if reason in REFUSAL_REASONS and count > 0:
        return False, (
            f"observation conflict: bind_reason={reason} with writer_entry_count={count}"
        )
    if count == 0 and completed:
        return False, "observation conflict: writer_entry_count=0 with write_completed"
    event_entry_count = sum(
        isinstance(ev, dict) and ev.get("event") == "writer_entered"
        for ev in events
    )
    if count != event_entry_count:
        return False, (
            f"observation conflict: writer_entry_count={count} "
            f"but events contain {event_entry_count} writer_entered entries"
        )
    return True, "eligibility, writer entry and completed writing are consistent"


def execution_eligible(case):
    """Source-grounded inference from the recorded bind decision.

    From gate.py: refusal returns before writer; success calls writer then
    returns reason='written'. writer_entry_count is not the eligibility decision.
    Missing or unexpected bind_reason is unresolved, not a refusal.
    """
    if not isinstance(case, dict):
        return None
    reason = case.get("observed", {}).get("bind_reason") if isinstance(case.get("observed"), dict) else None
    if reason == "written":
        return True
    if reason in REFUSAL_REASONS:
        return False
    return None


def matching_ticket_acks(events, ticket):
    """Indices of issuer_revocation_acknowledged events for this ticket only."""
    found = []
    for index, ev in enumerate(events):
        if (
            isinstance(ev, dict)
            and ev.get("event") == "issuer_revocation_acknowledged"
            and ev.get("revoked") == ticket
        ):
            found.append(index)
    return found


def withdrawal_before_crossing(case):
    """Order the matching-ticket acknowledgement against the crossing witness.

    Pinned serial flow (run.py): acknowledgement, then writer_entered, then
    write_completed. Writer entry is a witness of crossing, not the
    permission decision. Returns (status, reason):
    - established: matching ack is before the single writer_entered
    - absent: no matching-ticket acknowledgement
    - unresolved: order cannot be established
    """
    ticket, _present = _get_path(case, ("configuration", "ticket"))
    events = case.get("observed", {}).get("events", [])
    if not isinstance(events, list):
        return "unresolved", "ordering evidence malformed: observed.events"

    acks = matching_ticket_acks(events, ticket)
    crossings = [
        index for index, ev in enumerate(events)
        if isinstance(ev, dict) and ev.get("event") == "writer_entered"
    ]
    completions = [
        index for index, ev in enumerate(events)
        if isinstance(ev, dict) and ev.get("event") == "write_completed"
    ]

    if len(acks) > 1:
        return "unresolved", "ordering conflict: more than one matching-ticket acknowledgement"
    if len(crossings) > 1:
        return "unresolved", "ordering conflict: more than one writer_entered"
    if not acks:
        return "absent", "no matching-ticket withdrawal acknowledgement"
    if not crossings:
        return "unresolved", "ordering witness missing: writer_entered"

    ack_at = acks[0]
    cross_at = crossings[0]
    if ack_at > cross_at:
        return "unresolved", "acknowledgement after writer_entered; withdrawal before eligibility not established"
    if completions and ack_at > completions[0]:
        return "unresolved", "acknowledgement after write_completed; withdrawal before eligibility not established"
    if completions and cross_at > completions[0]:
        return "unresolved", "ordering conflict: writer_entered after write_completed"
    return "established", "matching acknowledgement precedes writer_entered"


def invalid_authorisation_established(case):
    """Requires matching ticket, matching bound instruction, acknowledged
    withdrawal for that ticket before the eligibility decision, and
    continuing effect under pinned issuer semantics.

    Both routes that can support a contradiction enforce the same order:
    the matching-ticket acknowledgement must precede writer_entered.
    A later refusing read after a completed write is not enough.
    A genuine refusal with no writer entry (case A) may still establish
    invalid authorisation from a refusing read after the acknowledgement.
    Returns True / False / None.
    """
    ok, _reason = binding_evidence(case)
    if not ok:
        return None

    ticket, _present = _get_path(case, ("configuration", "ticket"))
    events = case.get("observed", {}).get("events", [])
    if not isinstance(events, list):
        return None

    acks = matching_ticket_acks(events, ticket)
    if not acks:
        return False
    if len(acks) > 1:
        return None

    trust_prior_used = case.get("configuration", {}).get("trust_prior_used") is True
    later_refusal = False
    after_ack = False
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if after_ack and ev.get("event") == "live_read":
            revoked = ev.get("revoked", [])
            if isinstance(revoked, list) and ticket in revoked and ev.get("accepted") is False:
                later_refusal = True
                break
        if (
            ev.get("event") == "issuer_revocation_acknowledged"
            and ev.get("revoked") == ticket
        ):
            after_ack = True

    crossings = [
        index for index, ev in enumerate(events)
        if isinstance(ev, dict) and ev.get("event") == "writer_entered"
    ]
    if crossings:
        status, _reason = withdrawal_before_crossing(case)
        if status != "established":
            return None

    if trust_prior_used:
        status, _reason = withdrawal_before_crossing(case)
        if status != "established":
            return None
        return True
    if later_refusal:
        return True
    return None


def classify_detail(case):
    """Return verdict and the reason that produced it."""
    binding_ok, binding_reason = binding_evidence(case)
    if not binding_ok:
        return {"verdict": "UNRESOLVED", "reason": binding_reason}

    consistent, consistency_reason = observation_consistency(case)
    if not consistent:
        return {"verdict": "UNRESOLVED", "reason": consistency_reason}

    eligible = execution_eligible(case)
    trust_prior_used = (
        isinstance(case, dict)
        and isinstance(case.get("configuration"), dict)
        and case["configuration"].get("trust_prior_used") is True
    )
    # Common ordering gate for every withdrawal-based contradiction.
    # Cached path (trust_prior) and fresh path (later refusing read) both
    # pass through this check. It does not depend on trust_prior_used.
    if eligible is True:
        status, order_reason = withdrawal_before_crossing(case)
        if status == "unresolved":
            return {"verdict": "UNRESOLVED", "reason": order_reason}
        if status == "absent" and trust_prior_used:
            return {
                "verdict": "UNRESOLVED",
                "reason": order_reason,
            }

    invalid = invalid_authorisation_established(case)

    if eligible is None:
        return {
            "verdict": "UNRESOLVED",
            "reason": "eligibility unresolved: bind_reason missing or unexpected",
        }
    if invalid is None:
        return {
            "verdict": "UNRESOLVED",
            "reason": "invalid authorisation unresolved: withdrawal order or continuing effect not established",
        }
    if eligible is True and invalid is True:
        return {
            "verdict": "CLAIM_CONTRADICTED",
            "reason": "eligible and invalid authorisation established; matching acknowledgement precedes the eligibility crossing on this path",
        }
    return {
        "verdict": "NOT_CONTRADICTED_BY_THIS_OBSERVATION",
        "reason": "observation does not establish a contradiction",
    }


def classify(case):
    return classify_detail(case)["verdict"]


def main():
    data = json.loads(RECEIPT.read_text())
    cases = {c["case"]: c for c in data["cases"]}
    print("Synthetic classification on preserved receipt observations (v0.3.2)")
    print("R1: ticket and bound-instruction fields checked, not assumed")
    print("R2: written/zero-entry and refusal/writer-entry are UNRESOLVED")
    print("R3: both paths require matching acknowledgement before writer_entered")
    print("Eligibility = recorded bind decision (bind_reason), not writer_entry_count")
    print()
    verdicts = {}
    for label in ("A", "M", "B"):
        if label not in cases:
            continue
        detail = classify_detail(cases[label])
        verdicts[label] = detail["verdict"]
        c = cases[label]
        print(f"Case {label}:")
        print(f"  bind_reason: {c['observed'].get('bind_reason')}")
        print(f"  writer_entry_count: {c['observed'].get('writer_entry_count')}")
        print(f"  trust_prior_used: {c['configuration'].get('trust_prior_used')}")
        print(f"  classification: {detail['verdict']}")
        print(f"  reason: {detail['reason']}")
        print()
    print("Summary (derived from the classifications above):")
    for label in ("A", "M", "B"):
        if label in verdicts:
            print(f"Case {label}: {verdicts[label]}")
    print("BASIS_REQUIRES_REVALIDATION and BENIGN_CHANGE remain unexercised.")


if __name__ == "__main__":
    main()
