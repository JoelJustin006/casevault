"""
Append-only hash-chained ledger.
    entry_hash = SHA256(index | timestamp | actor | action | evidence | details | prev_hash)
"""
import hashlib
import json

from django.db import transaction
from django.utils import timezone

from .models import LedgerEntry

GENESIS_HASH = '0' * 64


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def hash_file(file_obj, chunk_size=65536) -> str:
    """SHA-256 of a file's raw bytes, streamed (safe for multi-GB CCTV)."""
    h = hashlib.sha256()
    for chunk in iter(lambda: file_obj.read(chunk_size), b''):
        h.update(chunk)
    return h.hexdigest()


def canonical_payload(index, timestamp_iso, actor_id, action, evidence_id, details, prev_hash):
    """Deterministic string. sort_keys + tight separators = reproducible hash."""
    return json.dumps({
        "index":    index,
        "ts":       timestamp_iso,
        "actor":    actor_id,
        "action":   action,
        "evidence": evidence_id,
        "details":  details,
        "prev":     prev_hash,
    }, sort_keys=True, separators=(',', ':'), default=str)


@transaction.atomic
def append(actor, action, evidence=None, details=None, request=None, timestamp=None) -> LedgerEntry:
    """Append one immutable block. Optional timestamp for backdated imports (seed only)."""
    from .security import request_fingerprint

    details = dict(details or {})
    fp = request_fingerprint(request)
    if fp:
        details.update(fp)

    last = LedgerEntry.objects.order_by('-index').first()
    index = last.index + 1 if last else 0
    prev_hash = last.entry_hash if last else GENESIS_HASH

    ts = timestamp or timezone.now()          # ← THIS LINE MUST EXIST
    payload = canonical_payload(
        index, ts.isoformat(),                 # ← ts, not timezone.now()
        actor.id if actor else None,
        action,
        evidence.id if evidence else None,
        details,
        prev_hash,
    )
    return LedgerEntry.objects.create(
        index=index, timestamp=ts, actor=actor, action=action,
        evidence=evidence, details=details,
        ip_address=fp.get('_ip'),
        user_agent=fp.get('_ua', ''),
        prev_hash=prev_hash, payload=payload,
        entry_hash=sha256_hex(payload),
    )

def verify_chain() -> dict:
    """Walk the whole chain and prove nothing was altered."""
    prev = GENESIS_HASH
    count = 0
    for e in LedgerEntry.objects.order_by('index'):
        if e.index != count:
            return {'ok': False, 'broken_at': e.index, 'reason': 'Index gap — a block was deleted'}
        # Signature verification
        if e.actor and e.signature:
            from .signing import verify_signature
            if not verify_signature(e.actor.public_key, e.payload, e.signature):
                return {'ok': False, 'broken_at': e.index, 'reason': f'Signature invalid for block #{e.index}'}
        if e.prev_hash != prev:
            return {'ok': False, 'broken_at': e.index, 'reason': 'prev_hash mismatch — chain relinked'}
        if sha256_hex(e.payload) != e.entry_hash:
            return {'ok': False, 'broken_at': e.index, 'reason': 'entry_hash mismatch — payload tampered'}
        recomputed = sha256_hex(canonical_payload(
            e.index, e.timestamp.isoformat(), e.actor_id, e.action,
            e.evidence_id, e.details, e.prev_hash,
        ))
        if recomputed != e.entry_hash:
            return {'ok': False, 'broken_at': e.index, 'reason': 'Field tampering detected'}
        prev = e.entry_hash
        count += 1
    return {'ok': True, 'length': count}


def verify_evidence_file(evidence) -> dict:
    """Re-hash the file on disk and compare to the stored fingerprint."""
    try:
        with evidence.file.open('rb') as f:
            actual = hash_file(f)
    except FileNotFoundError:
        return {'ok': False, 'reason': 'File missing from storage'}
    return {
        'ok': actual == evidence.file_hash,
        'expected': evidence.file_hash,
        'actual': actual,
        'reason': 'File intact' if actual == evidence.file_hash else 'FILE HAS BEEN ALTERED',
    }