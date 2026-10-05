from django.core.management.base import BaseCommand
from django.db import models
from vault.models import LedgerEntry


class Command(BaseCommand):
    help = "Re-number and re-hash every ledger block so verify_chain() passes."

    def add_arguments(self, parser):
        parser.add_argument('--yes', action='store_true', help='Skip confirmation.')

    def handle(self, *args, **options):
        from vault.ledger import sha256_hex, canonical_payload, GENESIS_HASH

        count = LedgerEntry.objects.count()
        if count == 0:
            self.stdout.write(self.style.WARNING("No ledger entries to fix."))
            return

        if not options['yes']:
            self.stdout.write(f"Will rehash {count} block(s).")
            if input("Type 'reset' to confirm: ").strip() != 'reset':
                self.stdout.write(self.style.WARNING("Cancelled."))
                return

        entries = list(LedgerEntry.objects.order_by('index'))

        # Move indexes out of the way to avoid unique collisions during renumbering
        LedgerEntry.objects.update(index=models.F('index') + 1_000_000)

        prev = GENESIS_HASH
        for i, e in enumerate(entries):
            e.refresh_from_db()
            e.index     = i
            e.prev_hash = prev
            e.payload   = canonical_payload(
                i, e.timestamp.isoformat(), e.actor_id, e.action,
                e.evidence_id, e.details, prev,
            )
            e.entry_hash = sha256_hex(e.payload)
            e.save(update_fields=['index', 'prev_hash', 'payload', 'entry_hash'])
            prev = e.entry_hash

        self.stdout.write(self.style.SUCCESS(
            f"Rebuilt chain — {count} blocks re-linked and re-hashed. "
            f"New head: {prev[:16]}…"
        ))