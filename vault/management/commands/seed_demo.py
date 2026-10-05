"""
Seed users only — no cases, no evidence, no ledger entries.
Use this for a clean demo where cases are built live.
"""
from django.core.management.base import BaseCommand
from vault.models import User


class Command(BaseCommand):
    help = "Seed demo users only. No cases, no evidence."

    def handle(self, *args, **options):
        if User.objects.filter(username='officer1').exists():
            self.stdout.write(self.style.WARNING("Users already seeded."))
            return

        # ----- Police -----
        User.objects.create_user('officer1', password='demo1234', role='OFFICER',
                                 first_name='Ravi', last_name='Kumar', badge_id='KP-1042',
                                 rank='SUB_INSPECTOR')
        User.objects.create_user('officer2', password='demo1234', role='OFFICER',
                                 first_name='Priya', last_name='Nair', badge_id='KP-2087',
                                 rank='INSPECTOR')
        User.objects.create_user('officer3', password='demo1234', role='OFFICER',
                                 first_name='Arjun', last_name='Singh', badge_id='KP-3311',
                                 rank='CONSTABLE')
        User.objects.create_user('officer4', password='demo1234', role='OFFICER',
                                 first_name='Vikram', last_name='Reddy', badge_id='KP-0001',
                                 rank='DSP')

        # ----- Forensics -----
        User.objects.create_user('forensic1', password='demo1234', role='FORENSICS',
                                 first_name='Anita', last_name='Rao', badge_id='FSL-778',
                                 rank='CHIEF_FORENSIC')
        User.objects.create_user('forensic2', password='demo1234', role='FORENSICS',
                                 first_name='Deepak', last_name='Menon', badge_id='FSL-990',
                                 rank='ANALYST')
        User.objects.create_user('forensic3', password='demo1234', role='FORENSICS',
                                 first_name='Kavita', last_name='Sharma', badge_id='FSL-445',
                                 rank='SR_ANALYST')
        User.objects.create_user('forensic4', password='demo1234', role='FORENSICS',
                                 first_name='Suresh', last_name='Iyer', badge_id='FSL-112',
                                 rank='JR_ANALYST')

        # ----- Judge / Advocate -----
        User.objects.create_user('judge1', password='demo1234', role='JUDGE',
                                 first_name='Meera', last_name='Iyer')
        User.objects.create_user('judge2', password='demo1234', role='JUDGE',
                                 first_name='Justice', last_name='Raghavan')
        User.objects.create_user('advocate1', password='demo1234', role='ADVOCATE',
                                 first_name='Adv. Sandeep', last_name='Pillai')
        User.objects.create_user('advocate2', password='demo1234', role='ADVOCATE',
                                 first_name='Adv. Neha', last_name='Bhatt')

        # ----- Admin -----
        User.objects.create_superuser('admin', password='demo1234', role='ADMIN',
                                      first_name='System', last_name='Administrator',
                                      rank='ADMIN_RANK')

        # Generate Ed25519 keypairs for every user
        for u in User.objects.all():
            try:
                u.ensure_keypair()
            except Exception:
                pass

        self.stdout.write(self.style.SUCCESS(
            f"Seeded {User.objects.count()} users. No cases or evidence — build them live."
        ))
        self.stdout.write(self.style.SUCCESS("Login: officer2 / demo1234"))