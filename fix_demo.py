# fix_demo.py — run with: py manage.py shell < fix_demo.py
from vault.models import User
from django.utils import timezone

ts = int(timezone.now().timestamp())
renamed = 0

for u in User.objects.filter(username__icontains='demo'):
    old = u.username
    u.username = f'archived_{old}_{ts}'
    u.is_active = False
    u.save()
    print(f"  Archived: {old} → {u.username}")
    renamed += 1

print(f"\nRenamed and deactivated {renamed} user(s).")
print("The username 'demo' is now free.")