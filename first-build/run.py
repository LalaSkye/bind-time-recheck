"""Run frozen cases A, B, and M. Do not treat M as protection evidence."""
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from gate import bind, check, digest

ROOT = Path(__file__).resolve().parent
SEED = b'original target bytes\n'
PAYLOAD = b'authorised replacement\n'
TICKET = 'fixture-ticket-001'
PACKET = json.dumps(
    {'ticket': TICKET, 'action': 'replace_bytes', 'target': 'target.txt', 'payload': PAYLOAD.decode()},
    sort_keys=True,
    separators=(',', ':'),
).encode()
SUPPLIED_PACKET_SHA256 = digest(PACKET)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run_case(target, case_id):
    target.write_bytes(SEED)
    before = target.read_bytes()
    events = []
    calls = []
    issuer = subprocess.Popen(
        [sys.executable, str(ROOT / 'issuer.py')],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )

    def request(op, **fields):
        issuer.stdin.write(json.dumps({'op': op, **fields}) + '\n')
        issuer.stdin.flush()
        response = issuer.stdout.readline()
        if not response:
            raise RuntimeError('issuer unavailable: no write authorised')
        return json.loads(response)

    def read_authority(ticket, packet_sha256):
        result = request('read', ticket=ticket, packet_sha256=packet_sha256)
        events.append({'event': 'live_read', **result})
        return result

    def writer(path, payload):
        calls.append('writer_entered')
        events.append({'event': 'writer_entered'})
        path.write_bytes(payload)
        events.append({'event': 'write_completed'})

    try:
        seed = request('seed', ticket=TICKET, packet_sha256=SUPPLIED_PACKET_SHA256)
        events.append({'event': 'issuer_seeded', **seed})
        first = check(PACKET, read_authority)
        require(first['authority']['accepted'], 'initial check must pass')
        events.append({'event': 'initial_check_passed'})
        if case_id in ('A', 'M'):
            revoked = request('revoke', ticket=TICKET)
            events.append({'event': 'issuer_revocation_acknowledged', **revoked})
        if case_id == 'M':
            outcome = bind(PACKET, target, read_authority, writer, trust_prior=first['authority'])
        else:
            outcome = bind(PACKET, target, read_authority, writer)
        after = target.read_bytes()
        event_names = [item['event'] for item in events]
        fresh_reads = [item for item in events if item['event'] == 'live_read']
        ack_at = event_names.index('issuer_revocation_acknowledged') if 'issuer_revocation_acknowledged' in event_names else None
        fresh_after_ack = False
        if ack_at is not None:
            fresh_after_ack = any(item['event'] == 'live_read' for item in events[ack_at + 1:])
        row = {
            'case': case_id,
            'configuration': {
                'ticket': TICKET,
                'trust_prior_used': outcome['trust_prior_used'],
                'trust_prior_supplied': first['authority'] if case_id == 'M' else None,
                'driver_supplied_packet_sha256': SUPPLIED_PACKET_SHA256,
                'issuer_seed_request': {'ticket': TICKET, 'packet_sha256': SUPPLIED_PACKET_SHA256},
            },
            'observed': {
                'check_packet_sha256_observed': first['packet_sha256_observed'],
                'bind_packet_sha256_observed': outcome['packet_sha256_observed'],
                'check_authority': first['authority'],
                'bind_authority': outcome['live'] if outcome['fresh_read'] else None,
                'bind_fresh_read': outcome['fresh_read'],
                'writer_entry_count': len(calls),
                'events': events,
                'bind_reason': outcome['reason'],
            },
            'derived': {
                'before_target_sha256': digest(before),
                'after_target_sha256': digest(after),
                'target_unchanged': before == after,
                'target_path': target.name,
                'role': 'sensitivity' if case_id == 'M' else 'protection',
                'verdict': None,
            },
        }
        if case_id == 'A':
            require(len(calls) == 0, 'A writer entry count')
            require(after == SEED, 'A target changed')
            require(outcome['reason'] == 'authority_not_current', 'A bind reason')
            require(outcome['accepted'] is False, 'A bind verdict')
            require(ack_at is not None, 'A missing withdrawal acknowledgement')
            require(outcome['fresh_read'] is True, 'A missing fresh read')
            require(fresh_after_ack, 'A fresh read not after acknowledgement')
            require(first['packet_sha256_observed'] == SUPPLIED_PACKET_SHA256, 'A check digest')
            require(outcome['packet_sha256_observed'] == SUPPLIED_PACKET_SHA256, 'A bind digest')
            require(outcome['trust_prior_used'] is False, 'A used trust_prior')
            require(event_names == [
                'issuer_seeded', 'live_read', 'initial_check_passed',
                'issuer_revocation_acknowledged', 'live_read',
            ], 'A event order')
            row['derived']['verdict'] = 'PROTECTION_HELD'
        elif case_id == 'B':
            require(len(calls) == 1, 'B writer entry count')
            require(after == PAYLOAD, 'B payload')
            require(outcome['accepted'] is True, 'B bind verdict')
            require(outcome['reason'] == 'written', 'B bind reason')
            require(outcome['fresh_read'] is True, 'B missing fresh read')
            require(len(fresh_reads) == 2, 'B fresh read count')
            require(first['packet_sha256_observed'] == SUPPLIED_PACKET_SHA256, 'B check digest')
            require(outcome['packet_sha256_observed'] == SUPPLIED_PACKET_SHA256, 'B bind digest')
            require(outcome['trust_prior_used'] is False, 'B used trust_prior')
            require(event_names == [
                'issuer_seeded', 'live_read', 'initial_check_passed', 'live_read',
                'writer_entered', 'write_completed',
            ], 'B event order')
            row['derived']['verdict'] = 'PROTECTION_HELD'
        elif case_id == 'M':
            require(len(calls) == 1, 'M did not reach writer')
            require(after == PAYLOAD, 'M target unchanged')
            require(fresh_after_ack is False, 'M fresh read after withdrawal')
            require(outcome['fresh_read'] is False, 'M bind_fresh_read')
            require(row['derived']['role'] == 'sensitivity', 'M classified as protection')
            require(event_names == [
                'issuer_seeded', 'live_read', 'initial_check_passed',
                'issuer_revocation_acknowledged', 'writer_entered', 'write_completed',
            ], 'M event order')
            row['derived']['verdict'] = 'SUBSTITUTION_VISIBLE'
        else:
            raise RuntimeError('unknown case')
        return row
    finally:
        issuer.stdin.close()
        issuer.wait(timeout=5)
        issuer.stdout.close()


def main():
    with tempfile.TemporaryDirectory(prefix='bind-time-recheck-') as directory:
        target = Path(directory) / 'target.txt'
        cases = [run_case(target, case_id) for case_id in ('A', 'B', 'M')]
    a, b, m = cases
    require(a['configuration']['driver_supplied_packet_sha256'] == b['configuration']['driver_supplied_packet_sha256'], 'packet digest mismatch')
    require(a['observed']['check_packet_sha256_observed'] == b['observed']['check_packet_sha256_observed'], 'check observation mismatch')
    require(a['derived']['before_target_sha256'] == b['derived']['before_target_sha256'], 'seed hash mismatch')
    require(a['derived']['target_path'] == b['derived']['target_path'], 'target path mismatch')
    require(a['configuration']['issuer_seed_request'] == b['configuration']['issuer_seed_request'], 'seed request mismatch')
    require(a['derived']['verdict'] == 'PROTECTION_HELD', 'A verdict')
    require(b['derived']['verdict'] == 'PROTECTION_HELD', 'B verdict')
    require(m['derived']['verdict'] == 'SUBSTITUTION_VISIBLE', 'M verdict')
    require(m['derived']['role'] == 'sensitivity', 'M role')
    receipt = {
        'status': 'FIRST_BUILD_PASS',
        'configuration': {
            'scope': 'Ordered revoke acknowledgement before bind read, plus one trust_prior sensitivity seam',
            'excluded': [
                'revocation after bind read',
                'OS atomicity',
                'production issuer security',
                'hostile issuer',
                'cryptographic identity',
                'evidence admission',
                'replay prevention',
                'distributed revocation',
                'concurrent revocation',
                'target mutation',
            ],
            'python': sys.version,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'source_sha256': {
                name: digest((ROOT / name).read_bytes())
                for name in ['issuer.py', 'gate.py', 'run.py', 'README.md']
            },
            'driver_supplied_packet_sha256': SUPPLIED_PACKET_SHA256,
            'ticket': TICKET,
        },
        'cases': cases,
    }
    text = json.dumps(receipt, indent=2)
    (ROOT / 'receipt.json').write_text(text + '\n')
    print(text)


if __name__ == '__main__':
    main()
