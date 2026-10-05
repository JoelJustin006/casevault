from django.apps import AppConfig
from django.db.models.signals import post_migrate
from django.dispatch import receiver


class VaultConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'vault'

    def ready(self):
        # Register the post-migrate seed hook
        post_migrate.connect(auto_seed, sender=self)


@receiver(post_migrate)
def auto_seed(sender, **kwargs):
    """After every migrate, seed demo data if the DB is empty."""
    if sender.name != 'vault':
        return

    from django.core.management import call_command
    from .models import User, Evidence

    # Already has data? Skip.
    if User.objects.filter(username='officer1').exists():
        return
    if Evidence.objects.exists():
        return

    try:
        call_command('seed_demo', verbosity=0)
        print("\n  ✓ CaseVault demo data seeded automatically.\n")
    except Exception as e:
        print(f"\n  ✗ Auto-seed failed: {e}\n")