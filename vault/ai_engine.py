"""
CaseVault AI Engine.
Heuristic risk modeling + anomaly detection + template-based narrative generation.
Pure Python. Deterministic. Auditable. No external APIs.
"""
from datetime import timedelta

from django.db.models import Count
from django.utils import timezone


SENSITIVITY_WEIGHTS = {'PUBLIC': 0, 'RESTRICTED': 10, 'CONFIDENTIAL': 22, 'TOP_SECRET': 35}
CATEGORY_WEIGHTS = {'MOBILE': 12, 'DISK': 10, 'USB': 12, 'CCTV': 8, 'LOG': 6, 'IMAGE': 4, 'DOC': 2, 'OTHER': 3}
SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


# ================================================================ RISK SCORING
def compute_risk_score(evidence):
    """Return (score 0-100, level, factors[]). Explainable per-factor attribution."""
    from .models import LedgerEntry

    score = 0
    factors = []

    s = SENSITIVITY_WEIGHTS.get(evidence.sensitivity, 0)
    if s:
        score += s
        factors.append({'factor': 'Classification', 'weight': s,
                        'note': f"{evidence.get_sensitivity_display()} tier"})

    c = CATEGORY_WEIGHTS.get(evidence.category, 0)
    if c:
        score += c
        factors.append({'factor': 'Category', 'weight': c,
                        'note': f"{evidence.get_category_display()} — higher PII surface"})

    if evidence.sensitivity in ('CONFIDENTIAL', 'TOP_SECRET') and not evidence.warrant_number:
        score += 15
        factors.append({'factor': 'Missing warrant', 'weight': 15,
                        'note': 'Sensitive item with no legal authorisation on file'})

    transfers = LedgerEntry.objects.filter(evidence=evidence, action='TRANSFER').count()
    if transfers >= 2:
        t = min(transfers * 5, 15)
        score += t
        factors.append({'factor': 'Custody churn', 'weight': t, 'note': f"{transfers} transfers"})

    downloads = LedgerEntry.objects.filter(evidence=evidence, action='DOWNLOAD').count()
    if downloads >= 3:
        d = min(downloads * 3, 15)
        score += d
        factors.append({'factor': 'Distribution breadth', 'weight': d, 'note': f"{downloads} downloads"})

    if not evidence.is_sealed:
        age_days = (timezone.now() - evidence.created_at).days
        if age_days > 60 and evidence.sensitivity in ('CONFIDENTIAL', 'TOP_SECRET'):
            score += 8
            factors.append({'factor': 'Unsealed longevity', 'weight': 8,
                            'note': f"{age_days} days unsealed at high tier"})

    tampering = LedgerEntry.objects.filter(evidence=evidence, action='TAMPER_ALERT').count()
    if tampering:
        t = min(tampering * 20, 40)
        score += t
        factors.append({'factor': 'Tamper history', 'weight': t, 'note': f"{tampering} alert(s)"})

    score = min(score, 100)
    level = 'CRITICAL' if score >= 70 else 'HIGH' if score >= 45 else 'MEDIUM' if score >= 20 else 'LOW'
    return score, level, factors


# ================================================================ NARRATIVE
def generate_custody_narrative(evidence):
    """Natural-language summary of the custody chain. Deterministic NLG."""
    entries = list(evidence.ledger_entries.select_related('actor').order_by('index'))
    if not entries:
        return "No custody events recorded."

    ingest = entries[0]
    actions = {}
    for e in entries:
        actions[e.action] = actions.get(e.action, 0) + 1

    views, downloads = actions.get('VIEW', 0), actions.get('DOWNLOAD', 0)
    transfers = actions.get('TRANSFER', 0)
    verifies = actions.get('VERIFY', 0) + actions.get('VERIFY_EXTERNAL', 0)

    parts = []
    actor_name = ingest.actor.get_full_name() if ingest.actor else 'an unknown operator'
    parts.append(
        f"This {evidence.get_category_display().lower()} was ingested on "
        f"{ingest.timestamp.strftime('%B %d, %Y')} by {actor_name}"
        f"{' under warrant ' + evidence.warrant_number if evidence.warrant_number else ''}."
    )

    if views or downloads or transfers:
        activity = []
        if views:     activity.append(f"{views} view{'s' if views != 1 else ''}")
        if downloads: activity.append(f"{downloads} download{'s' if downloads != 1 else ''}")
        if transfers: activity.append(f"{transfers} custodial transfer{'s' if transfers != 1 else ''}")
        parts.append(f"Since then the chain records {' and '.join(activity)}.")

    if verifies:
        parts.append(f"It has been independently verified {verifies} time{'s' if verifies != 1 else ''}.")

    if evidence.is_sealed and evidence.sealed_at:
        parts.append(f"The item was sealed for court on {evidence.sealed_at.strftime('%B %d, %Y')} "
                     f"with reason: \"{evidence.seal_reason}\".")
    else:
        parts.append("The item remains unsealed and under active custody.")

    score, level, _ = compute_risk_score(evidence)
    risk_note = {
        'LOW': 'The risk model flags no elevated concerns.',
        'MEDIUM': 'The risk model flags moderate attention items.',
        'HIGH': 'High-priority — review the custody chain.',
        'CRITICAL': 'Critical — recommend immediate supervisory review.',
    }[level]
    parts.append(f"Risk assessment: {score}/100 ({level}). {risk_note}")
    return ' '.join(parts)


# ================================================================ ANOMALY DETECTION
def detect_anomalies():
    """Behavioral pattern scan across the ledger + login trail."""
    from .models import LedgerEntry, LoginAttempt, User

    anomalies = []
    now = timezone.now()
    window_24h = now - timedelta(hours=24)
    window_7d = now - timedelta(days=7)

    # 1. Off-hours access
    for e in LedgerEntry.objects.filter(timestamp__gte=window_7d,
                                        action__in=['DOWNLOAD', 'TRANSFER', 'VIEW']):
        h = e.timestamp.hour
        if h >= 22 or h < 6:
            anomalies.append({
                'severity': 'MEDIUM', 'type': 'OFF_HOURS_ACCESS',
                'actor': e.actor.username if e.actor else 'unknown',
                'evidence': e.evidence.title if e.evidence else None,
                'evidence_id': e.evidence_id, 'timestamp': e.timestamp,
                'detail': f"{e.get_action_display()} at {e.timestamp.strftime('%H:%M')} (outside 06:00–22:00)",
            })

    # 2. Download spikes — same actor, ≥4 in 1h
    recent = LedgerEntry.objects.filter(
        timestamp__gte=window_7d, action='DOWNLOAD', actor__isnull=False,
    ).order_by('actor_id', 'timestamp')
    buckets = {}
    for d in recent:
        buckets.setdefault(d.actor_id, []).append(d)
    for items in buckets.values():
        for i in range(len(items)):
            window = [x for x in items if timedelta(0) <= x.timestamp - items[i].timestamp <= timedelta(hours=1)]
            if len(window) >= 4:
                anomalies.append({
                    'severity': 'HIGH', 'type': 'DOWNLOAD_SPIKE',
                    'actor': items[i].actor.username, 'evidence': None, 'evidence_id': None,
                    'timestamp': window[0].timestamp,
                    'detail': f"{len(window)} downloads within 1 hour — possible exfiltration pattern",
                })
                break

    # 3. Custody velocity — same evidence transferred ≥3× in 24h
    for row in LedgerEntry.objects.filter(timestamp__gte=window_24h, action='TRANSFER',
                                          evidence__isnull=False
                                          ).values('evidence_id').annotate(n=Count('id')):
        if row['n'] >= 3:
            ev = LedgerEntry.objects.filter(evidence_id=row['evidence_id']).first()
            anomalies.append({
                'severity': 'HIGH', 'type': 'CUSTODY_VELOCITY',
                'actor': 'multiple',
                'evidence': ev.evidence.title if ev and ev.evidence else None,
                'evidence_id': row['evidence_id'], 'timestamp': now,
                'detail': f"Evidence transferred {row['n']}× in 24h — unusual churn",
            })

    # 4. New IP login
    for user in User.objects.filter(is_active=True):
        logins = LoginAttempt.objects.filter(username=user.username, success=True).order_by('-timestamp')
        if logins.count() < 2:
            continue
        newest = logins[0]
        prior = set(logins[1:].values_list('ip_address', flat=True)[:50])
        if prior and newest.ip_address not in prior:
            anomalies.append({
                'severity': 'MEDIUM', 'type': 'NEW_IP_LOGIN',
                'actor': user.username, 'evidence': None, 'evidence_id': None,
                'timestamp': newest.timestamp,
                'detail': f"Login from unrecognised IP {newest.ip_address}",
            })

    # 5. Success immediately after failure
    for user in User.objects.filter(is_active=True):
        recent_l = list(LoginAttempt.objects.filter(username=user.username).order_by('-timestamp')[:10])
        for i, a in enumerate(recent_l):
            if a.success and i + 1 < len(recent_l) and not recent_l[i + 1].success:
                anomalies.append({
                    'severity': 'LOW', 'type': 'SUCCESS_AFTER_FAILURE',
                    'actor': user.username, 'evidence': None, 'evidence_id': None,
                    'timestamp': a.timestamp,
                    'detail': f"Successful login immediately after failed attempt from {a.ip_address}",
                })
                break

    anomalies.sort(key=lambda x: (SEV_ORDER.get(x['severity'], 4), -x['timestamp'].timestamp()))
    return anomalies


def risk_distribution():
    """Returns dict of counts per risk level across all evidence."""
    from .models import Evidence
    out = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for ev in Evidence.objects.all():
        _, level, _ = compute_risk_score(ev)
        out[level] += 1
    return out


def critical_items():
    """Evidence items with HIGH or CRITICAL risk, sorted descending."""
    from .models import Evidence
    rows = []
    for ev in Evidence.objects.all():
        s, level, factors = compute_risk_score(ev)
        if level in ('HIGH', 'CRITICAL'):
            rows.append({'evidence': ev, 'score': s, 'level': level, 'factors': factors})
    rows.sort(key=lambda r: -r['score'])
    return rows