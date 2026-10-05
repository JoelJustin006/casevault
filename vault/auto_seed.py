"""
Auto-seed on first request — only when CASEVAULT_AUTO_SEED=1.
"""
from django.conf import settings
from django.core.management import call_command
from django.db import connection


_SEED_CHECKED = False


class AutoSeedMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        global _SEED_CHECKED

        if not _SEED_CHECKED:
            _SEED_CHECKED = True
            try:
                self._maybe_seed()
            except Exception:
                pass

        return self.get_response(request)

    def _maybe_seed(self):
        # Off by default. Enable via CASEVAULT_AUTO_SEED=1 env var.
        if not getattr(settings, 'AUTO_SEED_ENABLED', False):
            return

        tables = connection.introspection.table_names()
        if 'vault_evidence' not in tables or 'vault_user' not in tables:
            return

        from .models import User, Evidence

        if User.objects.exists() or Evidence.objects.exists():
            return

        call_command('seed_demo', verbosity=0)
        print("\n  ✓ CaseVault demo data seeded (CASEVAULT_AUTO_SEED=1).\n")