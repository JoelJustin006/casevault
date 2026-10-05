from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    ROLE_OFFICER   = 'OFFICER'
    ROLE_FORENSICS = 'FORENSICS'
    ROLE_JUDGE     = 'JUDGE'
    ROLE_ADVOCATE  = 'ADVOCATE'
    ROLE_ADMIN     = 'ADMIN'

    ROLE_CHOICES = [
        (ROLE_OFFICER,   'Police Officer'),
        (ROLE_FORENSICS, 'Forensics Expert'),
        (ROLE_JUDGE,     'Judge'),
        (ROLE_ADVOCATE,  'Advocate / Legal Counsel'),
        (ROLE_ADMIN,     'System Administrator'),
    ]

    RANK_CHOICES = [
        # Police ranks
        ('CONSTABLE',       'Constable'),
        ('SUB_INSPECTOR',   'Sub-Inspector'),
        ('INSPECTOR',       'Inspector'),
        ('DSP',             'Deputy Superintendent'),
        # Forensic ranks
        ('JR_ANALYST',      'Junior Analyst'),
        ('ANALYST',         'Analyst'),
        ('SR_ANALYST',      'Senior Analyst'),
        ('CHIEF_FORENSIC',  'Chief Forensic Officer'),
        # Admin only
        ('ADMIN_RANK',      'Administrator'),
    ]

    role     = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_OFFICER)
    badge_id = models.CharField(max_length=50, blank=True)
    rank     = models.CharField(max_length=20, choices=RANK_CHOICES, blank=True, default='')

    public_key  = models.TextField(blank=True)
    private_key = models.TextField(blank=True)   # DEMO ONLY — use an HSM in production

    def ensure_keypair(self):
        """Generate a keypair if the user doesn't have one yet."""
        if self.public_key and self.private_key:
            return
        from .signing import generate_keypair
        self.private_key, self.public_key = generate_keypair()
        self.save(update_fields=['private_key', 'public_key'])

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

    @property
    def can_ingest(self):
        return self.role in (self.ROLE_OFFICER, self.ROLE_ADMIN)

    @property
    def can_transfer(self):
        return self.role in (self.ROLE_OFFICER, self.ROLE_FORENSICS, self.ROLE_ADMIN)

    @property
    def is_senior(self):
        """Senior ranks per role. Admin is always senior."""
        if self.role == 'ADMIN':
            return True
        if self.role == 'OFFICER':
            return self.rank in ('INSPECTOR', 'DSP')
        if self.role == 'FORENSICS':
            return self.rank in ('SR_ANALYST', 'CHIEF_FORENSIC')
        return False

    @property
    def is_junior_officer(self):
        """Junior ranks per role — eligible to be assigned to a case."""
        if not self.is_active:
            return False
        if self.role == 'OFFICER':
            return self.rank in ('CONSTABLE', 'SUB_INSPECTOR')
        if self.role == 'FORENSICS':
            return self.rank in ('JR_ANALYST', 'ANALYST')
        return False

    @property
    def rank_label(self):
        return self.get_rank_display() if self.rank else '—'


class Evidence(models.Model):
    case_number       = models.CharField(max_length=100, db_index=True)
    title             = models.CharField(max_length=200)
    description       = models.TextField(blank=True)
    file              = models.FileField(upload_to='evidence/%Y/%m/%d/')
    file_hash         = models.CharField(max_length=64, db_index=True)
    file_size         = models.BigIntegerField(default=0)

    uploaded_by       = models.ForeignKey(User, on_delete=models.PROTECT,
                                          related_name='uploaded_evidence')
    current_custodian = models.ForeignKey(User, on_delete=models.PROTECT,
                                          related_name='held_evidence')
    created_at        = models.DateTimeField(default=timezone.now)
    is_sealed         = models.BooleanField(default=False)
    CATEGORY_CHOICES = [
        ('CCTV',    'CCTV / Video'),
        ('MOBILE',  'Mobile Device Dump'),
        ('DISK',    'Hard Disk Image'),
        ('USB',     'Removable Media'),
        ('LOG',     'System / Access Log'),
        ('IMAGE',   'Photograph'),
        ('DOC',     'Document'),
        ('OTHER',   'Other'),
    ]
    SENSITIVITY_CHOICES = [
        ('PUBLIC',       'Public'),
        ('RESTRICTED',   'Restricted'),
        ('CONFIDENTIAL', 'Confidential'),
        ('TOP_SECRET',   'Top Secret'),
    ]

    category       = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='OTHER')
    sensitivity    = models.CharField(max_length=20, choices=SENSITIVITY_CHOICES, default='RESTRICTED')
    warrant_number = models.CharField(max_length=80, blank=True)
    warrant_expiry = models.DateField(null=True, blank=True)
    sealed_at      = models.DateTimeField(null=True, blank=True)
    sealed_by      = models.ForeignKey(User, null=True, blank=True,
                                       on_delete=models.SET_NULL, related_name='sealed_evidence')
    seal_reason    = models.CharField(max_length=300, blank=True)

    class Meta:
        verbose_name_plural = 'Evidence'
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.case_number}] {self.title}"

    @property
    def short_hash(self):
        return f"{self.file_hash[:12]}…{self.file_hash[-8:]}"
    
    @property
    def warrant_expired(self):
        if not self.warrant_expiry:
            return False
        from django.utils import timezone
        return self.warrant_expiry < timezone.now().date()

    @property
    def warrant_days_left(self):
        if not self.warrant_expiry:
            return None
        from django.utils import timezone
        return (self.warrant_expiry - timezone.now().date()).days


class LedgerEntry(models.Model):
    """Append-only. Never UPDATE, never DELETE."""
    ACTION_CHOICES = [
        ('INGEST',          'Evidence Ingested'),
        ('VIEW',            'Record Viewed'),
        ('DOWNLOAD',        'File Downloaded'),
        ('TRANSFER',        'Custody Transferred'),
        ('VERIFY',          'Integrity Verified'),
        ('VERIFY_EXTERNAL', 'External Verification'),
        ('TAMPER_ALERT',    'TAMPER DETECTED'),
        ('CASE_ASSIGNED',   'Case Officer Assigned'),
        ('CASE_UPDATED',    'Case Updated'),
        ('CASE_CLOSED',     'Case Closed'),
        ('TRANSFER_INITIATED', 'Transfer Initiated (awaiting co-sign)'),
        ('TRANSFER_ACCEPTED',  'Transfer Accepted (co-signed)'),
        ('TRANSFER_REJECTED',  'Transfer Rejected'),
        ('CASE_SEALED', 'Case Sealed (Merkle batch)'),
    ]

    signature = models.TextField(blank=True)
    index      = models.IntegerField(unique=True)
    timestamp  = models.DateTimeField(default=timezone.now)
    actor      = models.ForeignKey(User, null=True, blank=True,
                                   on_delete=models.SET_NULL)
    action     = models.CharField(max_length=30, choices=ACTION_CHOICES)
    evidence   = models.ForeignKey(Evidence, null=True, blank=True,
                                   on_delete=models.PROTECT, related_name='ledger_entries')
    warrant_expiry = models.DateField(null=True, blank=True)
    details    = models.JSONField(default=dict)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    prev_hash  = models.CharField(max_length=64)
    payload    = models.TextField()
    entry_hash = models.CharField(max_length=64, unique=True)

    class Meta:
        ordering = ['index']

    def __str__(self):
        return f"#{self.index} {self.action}"

class LoginAttempt(models.Model):
    """Audit trail for every login attempt — success or failure."""
    username   = models.CharField(max_length=150, db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.CharField(max_length=300, blank=True)
    success    = models.BooleanField()
    timestamp  = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{'✓' if self.success else '✗'} {self.username} @ {self.ip_address}"

class Case(models.Model):
    """A legal case. Evidence is grouped by case_number (denormalized key)."""
    STATUS_CHOICES = [
        ('OPEN',        'Open Investigation'),
        ('IN_COURT',    'In Trial'),
        ('CLOSED',      'Closed'),
        ('ARCHIVED',    'Archived'),
    ]

    merkle_root = models.CharField(max_length=64, blank=True)
    case_sealed_at = models.DateTimeField(null=True, blank=True)
    case_sealed_by = models.ForeignKey(User, null=True, blank=True,
                                       on_delete=models.SET_NULL,
                                       related_name='sealed_cases')

    senior_officer = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='supervised_cases',
    )

    closed_by        = models.ForeignKey(User, null=True, blank=True,
                                         on_delete=models.SET_NULL, related_name='closed_cases')
    closed_at        = models.DateTimeField(null=True, blank=True)
    closing_remarks  = models.TextField(blank=True)
    final_custody    = models.CharField(max_length=40, blank=True, choices=[
        ('ARCHIVE',       'Retained in Case Archive'),
        ('EVIDENCE_ROOM', 'Retained in Evidence Room'),
        ('COURT',         'Submitted to Court'),
        ('RETURNED',      'Returned to Owner'),
        ('APPELLATE',     'Transferred to Appellate Authority'),
        ('DESTROYED',     'Destroyed per Court Order'),
    ])
    custody_location = models.CharField(max_length=200, blank=True)

    case_number     = models.CharField(max_length=100, unique=True, db_index=True)
    title           = models.CharField(max_length=200)
    description     = models.TextField(blank=True)
    status          = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')
    lead_officer    = models.ForeignKey(User, null=True, blank=True,
                                        on_delete=models.SET_NULL, related_name='led_cases')
    prosecutor      = models.CharField(max_length=150, blank=True)
    court_date      = models.DateField(null=True, blank=True)
    created_at      = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.case_number} — {self.title}"

    @property
    def evidence_count(self):
        return Evidence.objects.filter(case_number=self.case_number).count()
    
    @property
    def warrant_expired(self):
        if not self.warrant_expiry:
            return False
        from django.utils import timezone
        return self.warrant_expiry < timezone.now().date()

    @property
    def warrant_days_left(self):
        if not self.warrant_expiry:
            return None
        from django.utils import timezone
        return (self.warrant_expiry - timezone.now().date()).days

    @property
    def status_color(self):
        return {
            'OPEN':     '#60a5fa',
            'IN_COURT': '#fbbf24',
            'CLOSED':   '#34d399',
            'ARCHIVED': '#8896b0',
        }.get(self.status, '#8896b0')

class Notification(models.Model):
    """Notification sent to the senior officer when evidence is changed/removed."""
    recipient   = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    actor       = models.ForeignKey(User, null=True, blank=True,
                                    on_delete=models.SET_NULL, related_name='triggered_notifications')
    case_number = models.CharField(max_length=100, blank=True, db_index=True)
    action      = models.CharField(max_length=40)
    message     = models.TextField()
    read        = models.BooleanField(default=False)
    created_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"→ {self.recipient.username}: {self.action}"

class PendingTransfer(models.Model):
    """A custody transfer awaiting countersignature from the receiving officer."""
    STATUS_CHOICES = [
        ('PENDING',  'Awaiting Countersignature'),
        ('ACCEPTED', 'Accepted'),
        ('REJECTED', 'Rejected'),
    ]

    evidence        = models.ForeignKey(Evidence, on_delete=models.CASCADE, related_name='pending_transfers')
    from_user       = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transfers_out')
    to_user         = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transfers_in')
    reason          = models.TextField()
    status          = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    initiated_at    = models.DateTimeField(auto_now_add=True)
    resolved_at     = models.DateTimeField(null=True, blank=True)
    initiate_block  = models.ForeignKey(LedgerEntry, null=True, on_delete=models.SET_NULL, related_name='+')
    resolve_block   = models.ForeignKey(LedgerEntry, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')

    class Meta:
        ordering = ['-initiated_at']

    def __str__(self):
        return f"{self.from_user.username} → {self.to_user.username} ({self.status})"