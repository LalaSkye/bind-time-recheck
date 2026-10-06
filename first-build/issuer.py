"""Test issuer process. Owns ticket binding and live revocation state."""
import json
import sys

binding = None
revoked = set()
for line in sys.stdin:
    request = json.loads(line)
    op = request['op']
    if op == 'seed' and binding is None:
        binding = (request['ticket'], request['packet_sha256'])
        result = {'seeded': True}
    elif op == 'revoke':
        revoked.add(request['ticket'])
        result = {'revoked': request['ticket']}
    elif op == 'read':
        accepted = binding == (request['ticket'], request['packet_sha256']) and request['ticket'] not in revoked
        result = {'accepted': accepted, 'revoked': sorted(revoked)}
    else:
        raise ValueError('unsupported issuer operation')
    print(json.dumps(result), flush=True)
