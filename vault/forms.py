from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User, Evidence
from django.db.models import Q

CATEGORY_FILE_EXTENSIONS = {
    'CCTV':   ['.mp4', '.avi', '.mkv', '.mov', '.webm', '.m4v', '.mpeg', '.mpg'],
    'MOBILE': ['.zip', '.tar', '.gz', '.7z', '.bin', '.img', '.tar.gz'],
    'DISK':   ['.img', '.iso', '.dd', '.bin', '.e01', '.raw'],
    'USB':    ['.zip', '.tar', '.img', '.bin', '.iso'],
    'LOG':    ['.log', '.txt', '.csv', '.json', '.xml'],
    'IMAGE':  ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.heic'],
    'DOC':    ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.xls', '.xlsx'],
    'OTHER':  None,   # any extension allowed
}

class RegisterForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'badge_id', 'role', 'rank')

    def clean(self):
        cleaned = super().clean()
        role = cleaned.get('role')
        rank = cleaned.get('rank')

        # Judge / Advocate have no rank
        if role in ('JUDGE', 'ADVOCATE'):
            cleaned['rank'] = ''
            return cleaned

        # Admin uses ADMIN_RANK
        if role == 'ADMIN':
            if rank != 'ADMIN_RANK':
                cleaned['rank'] = 'ADMIN_RANK'
            return cleaned

        # Police must have a police rank
        if role == 'OFFICER':
            if rank not in ('CONSTABLE', 'SUB_INSPECTOR', 'INSPECTOR', 'DSP'):
                raise forms.ValidationError("Please select a valid Police rank.")
            return cleaned

        # Forensics must have a forensic rank
        if role == 'FORENSICS':
            if rank not in ('JR_ANALYST', 'ANALYST', 'SR_ANALYST', 'CHIEF_FORENSIC'):
                raise forms.ValidationError("Please select a valid Forensic rank.")
            return cleaned

        return cleaned


class EvidenceForm(forms.ModelForm):

    warrant_expiry = forms.DateField(required=False, widget=forms.DateInput(attrs={
        'type': 'date',
        'autocomplete': 'off',
        'placeholder': 'e.g. 2026-12-31',
    }), label="Warrant Expiry Date")

    class Meta:
        model = Evidence
        fields = ('case_number', 'title', 'description', 'file',
                  'category', 'sensitivity', 'warrant_number')
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'case_number': forms.TextInput(attrs={
                'placeholder': 'e.g. CR-2025-0147',
                'autocomplete': 'off',
                'autocorrect': 'off',
                'autocapitalize': 'off',
                'spellcheck': 'false',
            }),
            'title': forms.TextInput(attrs={
                'placeholder': 'e.g. CCTV — Lobby Camera 03',
                'autocomplete': 'off',
            }),
            'warrant_number': forms.TextInput(attrs={
                'placeholder': 'WR-YYYY-NNNN',
                'autocomplete': 'off',
                'autocorrect': 'off',
                'autocapitalize': 'off',
                'spellcheck': 'false',
            }),
            'category': forms.Select(attrs={'autocomplete': 'off'}),
            'sensitivity': forms.Select(attrs={'autocomplete': 'off'}),
        }
        labels = {
            'warrant_number': 'Warrant Number',
            'case_number': 'Case Number',
        }
        help_texts = {
            'case_number': 'Use an existing case number to attach this to a case, or type a new one to create a case.',
            'warrant_number': 'Legal authorisation for collecting this evidence.',
        }

    def clean_file(self):
        f = self.cleaned_data['file']
        if f.size == 0:
            raise forms.ValidationError("Empty file.")
        category = self.cleaned_data.get('category')
        self._validate_extension(f, category)
        return f

    def _validate_extension(self, f, category):
        if not category:
            return
        allowed = CATEGORY_FILE_EXTENSIONS.get(category)
        if allowed is None:
            return   # OTHER — no restriction
        name = f.name.lower()
        if not any(name.endswith(ext) for ext in allowed):
            raise forms.ValidationError(
                f"File type mismatch. Category '{category}' expects: "
                f"{', '.join(allowed)}. You uploaded '{f.name}'."
            )


class TransferForm(forms.Form):
    new_custodian = forms.ModelChoiceField(queryset=User.objects.none())
    reason = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 2, 'class': 'form-control'}),
        help_text="Why is custody changing?",
    )

    def __init__(self, *args, current_user=None, **kwargs):
        super().__init__(*args, **kwargs)   # ← THIS LINE IS CRITICAL
        qs = User.objects.filter(
            role__in=['OFFICER', 'FORENSICS', 'JUDGE', 'ADVOCATE', 'ADMIN'],
            is_active=True,
        )
        qs = qs.exclude(username='__deleted__')
        qs = qs.exclude(username__startswith='archived_')
        if current_user:
            qs = qs.exclude(pk=current_user.pk)
        self.fields['new_custodian'].queryset = qs

from .models import Case


class CaseForm(forms.ModelForm):
    class Meta:
        model = Case
        fields = ('case_number', 'title', 'description', 'status',
                  'lead_officer', 'senior_officer', 'prosecutor', 'court_date')
        widgets = {
            'case_number': forms.TextInput(attrs={
                'class': 'form-control', 'placeholder': 'e.g. CR-2026-0501',
                'autocomplete': 'off',
            }),
            'title': forms.TextInput(attrs={
                'class': 'form-control', 'placeholder': 'e.g. Silk Board Bank Heist',
                'autocomplete': 'off',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'Brief summary of the incident…',
            }),
            'status': forms.Select(attrs={'class': 'form-select'}),
            'lead_officer': forms.Select(attrs={'class': 'form-select'}),
            'senior_officer': forms.Select(attrs={'class': 'form-select'}),
            'prosecutor': forms.TextInput(attrs={
                'class': 'form-control', 'placeholder': 'e.g. Adv. Rakesh Menon',
                'autocomplete': 'off',
            }),
            'court_date': forms.DateInput(attrs={
                'class': 'form-control', 'type': 'date', 'autocomplete': 'off',
            }),
        }
        labels = {
            'case_number': 'Case Number',
            'senior_officer': 'Supervising Senior Officer',
            'lead_officer': 'Officer Who Took Up the Case',
        }

    def __init__(self, *args, current_user=None, **kwargs):
        super().__init__(*args, **kwargs)
        from django.db.models import Q

        seniors = User.objects.filter(is_active=True).filter(
            Q(role='OFFICER',   rank__in=['INSPECTOR', 'DSP']) |
            Q(role='FORENSICS', rank__in=['SR_ANALYST', 'CHIEF_FORENSIC']) |
            Q(role='ADMIN')
        ).order_by('username')

        juniors = User.objects.filter(is_active=True).filter(
            Q(role='OFFICER',   rank__in=['CONSTABLE', 'SUB_INSPECTOR']) |
            Q(role='FORENSICS', rank__in=['JR_ANALYST', 'ANALYST'])
        ).order_by('username')

        if current_user and current_user.is_senior:
            juniors = juniors.exclude(pk=current_user.pk)

        self.fields['lead_officer'].queryset   = juniors
        self.fields['senior_officer'].queryset = seniors
        self.fields['lead_officer'].required   = False
        self.fields['senior_officer'].required = False
        self.fields['court_date'].required     = False
        self.fields['prosecutor'].required     = False
        self.fields['description'].required    = False

class CaseCloseForm(forms.Form):
    final_custody = forms.ChoiceField(
        choices=[
            ('ARCHIVE',       'Retained in Case Archive'),
            ('EVIDENCE_ROOM', 'Retained in Evidence Room'),
            ('COURT',         'Submitted to Court'),
            ('RETURNED',      'Returned to Owner'),
            ('APPELLATE',     'Transferred to Appellate Authority'),
            ('DESTROYED',     'Destroyed per Court Order'),
        ],
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='Final Disposition of Evidence',
    )
    custody_location = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Court Room 4, High Court Bengaluru'}),
        label='Location / Court Reference',
    )
    closing_remarks = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 4,
                                     'placeholder': 'Verdict, sentence, or reason for closure…'}),
        label='Closing Remarks',
    )

class InlineEvidenceForm(forms.ModelForm):
    class Meta:
        model = Evidence
        fields = ('title', 'category', 'sensitivity', 'warrant_number', 'file')
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off'}),
            'warrant_number': forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off'}),
        }

    def clean_file(self):
        f = self.cleaned_data['file']
        if f.size == 0:
            raise forms.ValidationError("Empty file.")
        category = self.cleaned_data.get('category')
        if not category:
            return f
        allowed = CATEGORY_FILE_EXTENSIONS.get(category)
        if allowed is None:
            return f
        name = f.name.lower()
        if not any(name.endswith(ext) for ext in allowed):
            raise forms.ValidationError(
                f"File type mismatch. Category '{category}' expects: "
                f"{', '.join(allowed)}. You uploaded '{f.name}'."
            )
        return f