from django.core.management.base import BaseCommand
from vault.models import LoginAttempt


class Command(BaseCommand):
    help = "Clear all LoginAttempt records (unlocks every locked-out account)."

    def add_arguments(self, parser):
        parser.add_argument(
            '--keep',
            type=int,
            default=0,
            help='Keep the N most recent attempts (default: delete all).',
        )
        parser.add_argument(
            '--yes',
            action='store_true',
            help='Skip confirmation prompt.',
        )

    def handle(self, *args, **options):
        total = LoginAttempt.objects.count()

        if total == 0:
            self.stdout.write(self.style.WARNING("No login attempts in database."))
            return

        keep = options['keep']

        if not options['yes']:
            self.stdout.write(f"Found {total} login attempt(s).")
            if keep:
                self.stdout.write(f"Will keep the {keep} most recent.")
            confirm = input("Delete the rest? [y/N]: ").strip().lower()
            if confirm != 'y':
                self.stdout.write(self.style.WARNING("Cancelled."))
                return

        if keep > 0:
            ids_to_keep = list(
                LoginAttempt.objects.order_by('-timestamp')
                .values_list('id', flat=True)[:keep]
            )
            deleted, _ = LoginAttempt.objects.exclude(id__in=ids_to_keep).delete()
        else:
            deleted, _ = LoginAttempt.objects.all().delete()

        self.stdout.write(self.style.SUCCESS(
            f"Deleted {deleted} login attempt(s). "
            f"All accounts are now unlocked."
        ))