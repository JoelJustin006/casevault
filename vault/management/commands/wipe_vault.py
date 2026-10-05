from django.core.management.base import BaseCommand
from vault.models import Evidence, LedgerEntry, LoginAttempt, User


class Command(BaseCommand):
    help = "Delete every user, evidence item, ledger entry, and login attempt."

    def add_arguments(self, parser):
        parser.add_argument('--yes', action='store_true', help='Skip confirmation.')

    def handle(self, *args, **options):
        if not options['yes']:
            self.stdout.write(self.style.WARNING(
                f"This will DELETE:\n"
                f"  - {User.objects.count()} users\n"
                f"  - {Evidence.objects.count()} evidence items\n"
                f"  - {LedgerEntry.objects.count()} ledger entries\n"
                f"  - {LoginAttempt.objects.count()} login attempts"
            ))
            if input("Type 'wipe' to confirm: ").strip() != 'wipe':
                self.stdout.write(self.style.WARNING("Cancelled."))
                return

        # Order matters — kill children before parents
        lc = LedgerEntry.objects.all().delete()[0]
        ec = Evidence.objects.all().delete()[0]
        ac = LoginAttempt.objects.all().delete()[0]
        uc = User.objects.all().delete()[0]

        self.stdout.write(self.style.SUCCESS(
            f"Wiped: {uc} users, {ec} evidence, {lc} ledger entries, {ac} login attempts.\n"
            f"Register your own account at /register/ to start fresh."
        ))