"""Checker gets a read interface only; never issues or revokes authority."""
import hashlib
import json


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check(packet_bytes, read_authority):
    observed = digest(packet_bytes)
    packet = json.loads(packet_bytes)
    live = read_authority(packet['ticket'], observed)
    return {'packet_sha256_observed': observed, 'authority': live}


def bind(packet_bytes, target, read_authority, writer, *, trust_prior=None):
    observed = digest(packet_bytes)
    packet = json.loads(packet_bytes)
    trust_prior_used = trust_prior is not None
    if packet['action'] != 'replace_bytes' or packet['target'] != target.name:
        return {
            'accepted': False,
            'reason': 'binding_mismatch',
            'packet_sha256_observed': observed,
            'fresh_read': False,
            'trust_prior_used': trust_prior_used,
            'live': None,
        }
    if trust_prior_used:
        live = trust_prior
        fresh_read = False
    else:
        checked = check(packet_bytes, read_authority)
        live = checked['authority']
        fresh_read = True
    if not live['accepted']:
        return {
            'accepted': False,
            'reason': 'authority_not_current',
            'live': live,
            'packet_sha256_observed': observed,
            'fresh_read': fresh_read,
            'trust_prior_used': trust_prior_used,
        }
    # Deliberately no atomicity claim: revoke AFTER this read is outside scope.
    writer(target, packet['payload'].encode('utf-8'))
    return {
        'accepted': True,
        'reason': 'written',
        'live': live,
        'packet_sha256_observed': observed,
        'fresh_read': fresh_read,
        'trust_prior_used': trust_prior_used,
    }
