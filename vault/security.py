"""Security utilities — IP extraction, lockout policy, request fingerprinting."""
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

LOCKOUT_THRESHOLD = 5      # failed attempts
LOCKOUT_WINDOW_SEC = 15    # minutes


def get_client_ip(request) -> str:
    """Respect reverse-proxy XFF header; fall back to REMOTE_ADDR."""
    if request is None:
        return '0.0.0.0'
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def request_fingerprint(request) -> dict:
    """Compact evidence-safe fingerprint of the request source."""
    if request is None:
        return {}
    ua = request.META.get('HTTP_USER_AGENT', '')[:200]
    return {
        '_ip': get_client_ip(request),
        '_ua': ua,
    }


def is_locked_out(username: str, ip: str) -> bool:
    """True if this username OR IP has exceeded the failed-login threshold recently."""
    from .models import LoginAttempt
    since = timezone.now() - timedelta(minutes=LOCKOUT_WINDOW_SEC)
    qs = LoginAttempt.objects.filter(
        success=False,
        timestamp__gte=since,
    ).filter(Q(username=username) | Q(ip_address=ip))
    return qs.count() >= LOCKOUT_THRESHOLD


def recent_lockouts():
    """Return [{username, ip, count, last}] for currently-locked identities."""
    from .models import LoginAttempt
    since = timezone.now() - timedelta(minutes=LOCKOUT_WINDOW_SEC)
    failures = (
        LoginAttempt.objects
        .filter(success=False, timestamp__gte=since)
        .values('username', 'ip_address')
    )
    buckets = {}
    for f in failures:
        key = (f['username'], f['ip_address'])
        buckets[key] = buckets.get(key, 0) + 1
    return [
        {'username': u, 'ip': ip, 'count': n}
        for (u, ip), n in buckets.items() if n >= LOCKOUT_THRESHOLD
    ]