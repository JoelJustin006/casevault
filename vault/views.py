"""
CaseVault — All views.

Sections:
  1. Imports
  2. Auth & registration
  3. Home & dashboard
  4. Evidence operations (upload, view, download, transfer, seal, delete)
  5. Case operations (list, create, edit, close, delete, seal, public view)
  6. Officer activity
  7. Ledger & verification
  8. AI insights
  9. Security & audit
 10. Analytics
 11. Utility (chain rebuild)
"""
import base64
import json
import os
import zipfile
from datetime import timedelta
from io import BytesIO

from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import models
from django.db.models import Count, Q
from django.http import FileResponse, HttpResponse, HttpResponseForbidden
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils import timezone
from .models import (
    Case, Evidence, LedgerEntry, LoginAttempt, Notification,
    PendingTransfer, User,
)

import qrcode

from . import ai_engine, ledger
from .decorators import role_required
from .forms import (
    CaseCloseForm, CaseForm, EvidenceForm, InlineEvidenceForm,
    RegisterForm, TransferForm,
)
from .models import (
    Case, Evidence, LedgerEntry, LoginAttempt, PendingTransfer,
    User,
)
from .security import get_client_ip, is_locked_out, recent_lockouts


# ================================================================
# 1. AUTH & REGISTRATION
# ================================================================
def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username'].strip()
            existing = User.objects.filter(username__iexact=username).first()

            if existing and not existing.is_active:
                # Reclaim deactivated account
                existing.set_password(form.cleaned_data['password1'])
                existing.first_name = form.cleaned_data.get('first_name', existing.first_name)
                existing.last_name  = form.cleaned_data.get('last_name', existing.last_name)
                existing.email      = form.cleaned_data.get('email', existing.email)
                existing.badge_id   = form.cleaned_data.get('badge_id', existing.badge_id)
                existing.role       = form.cleaned_data.get('role', existing.role)
                existing.rank       = form.cleaned_data.get('rank', existing.rank)
                existing.is_active  = True
                existing.save()

                login(request, existing)
                ledger.append(existing, 'VERIFY', None, {
                    'note': 'Deactivated account reactivated via registration',
                }, request=request)
                messages.success(request, f"Welcome back, {existing.username}.")
                return redirect('dashboard')

            # Normal new registration
            user = form.save()
            login(request, user)
            ledger.append(user, 'VERIFY', None, {
                'note': f'New account registered as {user.role}',
            }, request=request)
            return redirect('dashboard')
    else:
        form = RegisterForm()
    return render(request, 'vault/register.html', {'form': form})


class AuditedLoginView(auth_views.LoginView):
    template_name = 'vault/login.html'

    def post(self, request, *args, **kwargs):
        username = request.POST.get('username', '').strip()
        ip = get_client_ip(request)
        ua = request.META.get('HTTP_USER_AGENT', '')[:300]

        if is_locked_out(username, ip):
            return render(request, self.template_name, {
                'form': auth_views.AuthenticationForm(request),
                'locked_out': True,
            }, status=429)

        response = super().post(request, *args, **kwargs)
        success = request.user.is_authenticated

        LoginAttempt.objects.create(
            username=username or '(blank)',
            ip_address=ip,
            user_agent=ua,
            success=success,
        )
        return response


# ================================================================
# 2. HOME & DASHBOARD
# ================================================================
def home(request):
    """Public landing page — always visible."""
    chain = ledger.verify_chain()
    stats = {
        'evidence': Evidence.objects.count(),
        'blocks':   LedgerEntry.objects.count(),
        'cases':    Case.objects.count(),
        'chain_ok': chain['ok'],
    }
    return render(request, 'vault/home.html', {'stats': stats, 'chain': chain})


@login_required
def dashboard(request):
    """Evidence dashboard — scoped to cases the user is involved with."""
    user = request.user
    base = Evidence.objects.select_related('uploaded_by', 'current_custodian')

    # Visibility scope
    if user.role == 'ADMIN':
        scoped = base
    elif user.role in ('JUDGE', 'ADVOCATE'):
        scoped = base.filter(current_custodian=user)
    elif user.is_senior:
        case_nums = list(
            Case.objects.filter(
                Q(senior_officer=user) | Q(lead_officer=user)
            ).values_list('case_number', flat=True)
        )
        scoped = base.filter(
            Q(case_number__in=case_nums) | Q(current_custodian=user)
        ).distinct()
    else:
        case_nums = list(
            Case.objects.filter(lead_officer=user).values_list('case_number', flat=True)
        )
        scoped = base.filter(
            Q(case_number__in=case_nums) | Q(current_custodian=user)
        ).distinct()

    q = request.GET.get('q', '').strip()
    if q:
        scoped = scoped.filter(
            Q(case_number__icontains=q) |
            Q(title__icontains=q) |
            Q(file_hash__icontains=q)
        )

    chain = ledger.verify_chain()

    rows = []
    for ev in scoped[:100]:
        s, level, _ = ai_engine.compute_risk_score(ev)
        rows.append({'ev': ev, 'risk_score': s, 'risk_level': level})

    # Warrant alerts
    today = timezone.now().date()
    expiring_soon = Evidence.objects.filter(
        warrant_expiry__isnull=False,
        warrant_expiry__gte=today,
        warrant_expiry__lte=today + timedelta(days=7),
    )
    expired = Evidence.objects.filter(
        warrant_expiry__isnull=False,
        warrant_expiry__lt=today,
    )

    stats = {
        'total':    scoped.count(),
        'entries':  LedgerEntry.objects.count(),
        'mine':     scoped.filter(current_custodian=user).count(),
        'chain_ok': chain['ok'],
    }

    return render(request, 'vault/dashboard.html', {
        'rows': rows,
        'stats': stats,
        'chain': chain,
        'q': q,
        'warrants_expiring': expiring_soon[:5],
        'warrants_expired_count': expired.count(),
        'warrants_expiring_count': expiring_soon.count(),
    })


# ================================================================
# 3. EVIDENCE OPERATIONS
# ================================================================
@role_required('OFFICER', 'ADMIN')
def evidence_upload(request):
    if request.method == 'POST':
        form = EvidenceForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded = request.FILES['file']
            digest = ledger.hash_file(uploaded)
            uploaded.seek(0)

            ev = form.save(commit=False)
            ev.file_hash = digest
            ev.file_size = uploaded.size
            ev.uploaded_by = request.user
            ev.current_custodian = request.user
            ev.save()

            ledger.append(request.user, 'INGEST', ev, {
                'sha256':   digest,
                'filename': os.path.basename(ev.file.name),
                'size':     uploaded.size,
                'case':     ev.case_number,
                'warrant':  ev.warrant_number or '',
            }, request=request)

            # Auto-create the Case row if it doesn't exist
            if not Case.objects.filter(case_number=ev.case_number).exists():
                new_case = Case.objects.create(
                    case_number=ev.case_number,
                    title=f"Case {ev.case_number}",
                    description=ev.description or "",
                    status='OPEN',
                    lead_officer=request.user,
                )
                ledger.append(request.user, 'CASE_UPDATED', ev, {
                    'action': 'CASE_CREATED',
                    'case':   ev.case_number,
                }, request=request)

            messages.success(request, f"Evidence ingested. SHA-256: {digest[:16]}…")
            return redirect('evidence_detail', pk=ev.pk)
    else:
        form = EvidenceForm()
    return render(request, 'vault/upload.html', {'form': form})


@login_required
def evidence_detail(request, pk):
    ev = get_object_or_404(Evidence, pk=pk)
    entries = ev.ledger_entries.select_related('actor').order_by('index')

    file_check = ledger.verify_evidence_file(ev)

    if not file_check['ok']:
        ledger.append(request.user, 'TAMPER_ALERT', ev, {
            'expected': file_check.get('expected', ''),
            'actual':   file_check.get('actual', ''),
            'context':  'Detected during detail view',
        }, request=request)

    ledger.append(request.user, 'VIEW', ev, {'note': 'Opened evidence record'},
                  request=request)

    # AI enrichment
    risk_score, risk_level, risk_factors = ai_engine.compute_risk_score(ev)
    narrative = ai_engine.generate_custody_narrative(ev)

    # QR code for public verify portal
    qr_url = request.build_absolute_uri('/verify/')
    qr_img = qrcode.make(qr_url)
    qr_buf = BytesIO()
    qr_img.save(qr_buf, format='PNG')
    qr_data = 'data:image/png;base64,' + base64.b64encode(qr_buf.getvalue()).decode()

        # Transfer log for this evidence
    ev_transfers = ev.ledger_entries.filter(
        action__in=['TRANSFER_INITIATED', 'TRANSFER_ACCEPTED', 'TRANSFER_REJECTED'],
    ).order_by('-timestamp')

    return render(request, 'vault/detail.html', {
        'ev':            ev,
        'entries':       entries,
        'file_check':    file_check,
        'transfer_form': TransferForm(current_user=request.user),
        'qr_data':       qr_data,
        'risk_score':    risk_score,
        'risk_level':    risk_level,
        'risk_factors':  risk_factors,
        'narrative':     narrative,
    })


@login_required
def evidence_download(request, pk):
    ev = get_object_or_404(Evidence, pk=pk)

    check = ledger.verify_evidence_file(ev)
    if not check['ok']:
        ledger.append(request.user, 'TAMPER_ALERT', ev, {
            'expected': check.get('expected', ''),
            'actual':   check.get('actual', ''),
        }, request=request)
        return HttpResponseForbidden("Integrity check failed. Download blocked and logged.")

    download_ts = timezone.now().isoformat()
    entry = ledger.append(request.user, 'DOWNLOAD', ev, {
        'sha256':   ev.file_hash,
        'filename': os.path.basename(ev.file.name),
        'watermark': {
            'downloaded_by': request.user.username,
            'downloaded_at': download_ts,
        },
    }, request=request)

    resp = FileResponse(ev.file.open('rb'), as_attachment=True,
                        filename=os.path.basename(ev.file.name))
    resp['X-CaseVault-SHA256']        = ev.file_hash
    resp['X-CaseVault-Downloaded-By'] = request.user.username
    resp['X-CaseVault-Downloaded-At'] = download_ts
    resp['X-CaseVault-Ledger-Index']  = str(entry.index)
    resp['X-CaseVault-Ledger-Hash']   = entry.entry_hash
    return resp


@login_required
def evidence_transfer(request, pk):
    """Initiate a custody transfer — awaits the receiver's countersignature."""
    ev = get_object_or_404(Evidence, pk=pk)

    if not (request.user.can_transfer and ev.current_custodian_id == request.user.id):
        raise PermissionDenied("You are not the current custodian of this evidence.")

    if ev.is_sealed:
        messages.error(request, "Cannot transfer sealed evidence.")
        return redirect('evidence_detail', pk=ev.pk)

    if request.method == 'POST':
        form = TransferForm(request.POST, current_user=request.user)
        if form.is_valid():
            new_holder = form.cleaned_data['new_custodian']
            reason     = form.cleaned_data['reason']

            block = ledger.append(request.user, 'TRANSFER_INITIATED', ev, {
                'from':   request.user.username,
                'to':     new_holder.username,
                'reason': reason,
                'status': 'PENDING',
            }, request=request)

            PendingTransfer.objects.create(
                evidence=ev,
                from_user=request.user,
                to_user=new_holder,
                reason=reason,
                initiate_block=block,
            )

            messages.success(
                request,
                f"Transfer initiated. {new_holder.username} must countersign to complete."
            )
            return redirect('evidence_detail', pk=ev.pk)

    return redirect('evidence_detail', pk=ev.pk)


@login_required
def transfer_accept(request, pk):
    transfer = get_object_or_404(PendingTransfer, pk=pk)

    if transfer.to_user_id != request.user.id:
        raise PermissionDenied("Only the receiving officer can countersign this transfer.")

    if transfer.status != 'PENDING':
        messages.error(request, "This transfer is no longer pending.")
        return redirect('pending_actions')

    if request.method == 'POST':
        ev = transfer.evidence

        block = ledger.append(request.user, 'TRANSFER_ACCEPTED', ev, {
            'from':           transfer.from_user.username,
            'to':             request.user.username,
            'reason':         transfer.reason,
            'initiate_block': transfer.initiate_block.index if transfer.initiate_block else None,
            'counter_signer': request.user.username,
        }, request=request)

        ev.current_custodian = request.user
        ev.save(update_fields=['current_custodian'])

        transfer.status        = 'ACCEPTED'
        transfer.resolved_at   = timezone.now()
        transfer.resolve_block = block
        transfer.save()

        messages.success(request, f"Transfer accepted. You now hold '{ev.title}'.")
        return redirect('evidence_detail', pk=ev.pk)

    return render(request, 'vault/transfer_accept.html', {'transfer': transfer})


@login_required
def transfer_reject(request, pk):
    transfer = get_object_or_404(PendingTransfer, pk=pk)

    if transfer.to_user_id != request.user.id:
        raise PermissionDenied("Only the receiving officer can reject this transfer.")

    if transfer.status != 'PENDING':
        return redirect('pending_actions')

    if request.method == 'POST':
        ev = transfer.evidence
        block = ledger.append(request.user, 'TRANSFER_REJECTED', ev, {
            'from':        transfer.from_user.username,
            'to':          request.user.username,
            'reason':      transfer.reason,
            'rejected_by': request.user.username,
        }, request=request)

        transfer.status        = 'REJECTED'
        transfer.resolved_at   = timezone.now()
        transfer.resolve_block = block
        transfer.save()

        messages.info(request, f"Transfer of '{ev.title}' rejected.")
        return redirect('pending_actions')

    return redirect('pending_actions')


@login_required
def pending_actions(request):
    outgoing = PendingTransfer.objects.filter(
        from_user=request.user, status='PENDING'
    ).select_related('evidence', 'to_user')

    incoming = PendingTransfer.objects.filter(
        to_user=request.user, status='PENDING'
    ).select_related('evidence', 'from_user')

    return render(request, 'vault/pending_actions.html', {
        'outgoing': outgoing,
        'incoming': incoming,
    })


@login_required
def evidence_seal(request, pk):
    """Seal evidence — makes it immutable from further transfers."""
    ev = get_object_or_404(Evidence, pk=pk)

    if not (request.user.role in ('OFFICER', 'ADMIN') and ev.current_custodian_id == request.user.id):
        raise PermissionDenied("Only the current custodian can seal this evidence.")

    if request.method == 'POST':
        reason = request.POST.get('reason', '').strip() or 'Submitted to court'
        ev.is_sealed  = True
        ev.sealed_at  = timezone.now()
        ev.sealed_by  = request.user
        ev.seal_reason = reason
        ev.save(update_fields=['is_sealed', 'sealed_at', 'sealed_by', 'seal_reason'])

        ledger.append(request.user, 'VERIFY', ev, {
            'action': 'EVIDENCE_SEALED',
            'reason': reason,
            'sha256': ev.file_hash,
        }, request=request)
        messages.success(request, "Evidence sealed. It is now immutable.")

    return redirect('evidence_detail', pk=ev.pk)


@role_required('OFFICER', 'ADMIN')
def evidence_delete(request, pk):
    """Delete evidence. Senior-only."""
    ev = get_object_or_404(Evidence, pk=pk)

    if not (request.user.is_senior or request.user.role == 'ADMIN'):
        messages.error(request, "Only senior officers can delete evidence.")
        return redirect('dashboard')

    if request.method != 'POST':
        return redirect('dashboard')

    if request.POST.get('confirm') != 'DELETE':
        messages.error(request, "You must type DELETE to confirm.")
        return redirect('dashboard')

    case_number = ev.case_number
    title       = ev.title

    block_count = LedgerEntry.objects.filter(evidence=ev).count()
    LedgerEntry.objects.filter(evidence=ev).delete()

    try:
        ev.file.delete(save=False)
    except Exception:
        pass

    ev.delete()

    _rebuild_chain()

    messages.success(
        request,
        f"Deleted '{title}' (case {case_number}). {block_count} ledger block(s) removed. Chain rebuilt."
    )
    return redirect('dashboard')


# ================================================================
# 4. CASE OPERATIONS
# ================================================================
@login_required
def cases_list(request):
    """List cases visible to the current user."""
    user = request.user

    # Auto-backfill: create Case rows for any case_number in Evidence that has no Case row
    existing_case_numbers = set(Case.objects.values_list('case_number', flat=True))
    evidence_case_numbers = set(
        Evidence.objects.values_list('case_number', flat=True).distinct()
    )
    missing = evidence_case_numbers - existing_case_numbers
    for cn in missing:
        ev = Evidence.objects.filter(case_number=cn).first()
        Case.objects.create(
            case_number=cn,
            title=f"Case {cn}",
            description=ev.description if ev else "",
            status='OPEN',
            lead_officer=ev.uploaded_by if ev else None,
            created_at=ev.created_at if ev else timezone.now(),
        )

    # Cases where user currently holds evidence
    held_case_nums = list(
        Evidence.objects.filter(current_custodian=user)
        .values_list('case_number', flat=True)
        .distinct()
    )

    # Visibility scope
    if user.role == 'ADMIN':
        qs = Case.objects.all()
    elif user.role in ('JUDGE', 'ADVOCATE'):
        qs = Case.objects.filter(case_number__in=held_case_nums)
    elif user.is_senior:
        qs = Case.objects.filter(
            Q(senior_officer=user) |
            Q(lead_officer=user) |
            Q(case_number__in=held_case_nums) |
            Q(senior_officer__isnull=True, lead_officer__isnull=True)
        ).distinct()
    else:
        qs = Case.objects.filter(
            Q(lead_officer=user) |
            Q(case_number__in=held_case_nums)
        ).distinct()

    cases = []
    for c in qs.order_by('-created_at'):
        evidence_qs = Evidence.objects.filter(case_number=c.case_number)
        cases.append({
            'case':           c,
            'evidence_count': evidence_qs.count(),
            'sealed_count':   evidence_qs.filter(is_sealed=True).count(),
        })

    chain = ledger.verify_chain()
    return render(request, 'vault/cases.html', {'cases': cases, 'chain': chain})


@role_required('OFFICER', 'ADMIN')
def case_create(request):
    if request.method == 'POST':
        form = CaseForm(request.POST, current_user=request.user)
        if form.is_valid():
            case = form.save()
            ledger.append(request.user, 'CASE_UPDATED', None, {
                'action':     'CASE_CREATED',
                'case':       case.case_number,
                'title':      case.title,
                'senior':     case.senior_officer.username if case.senior_officer else '',
                'prosecutor': case.prosecutor or '',
                'court_date': case.court_date.isoformat() if case.court_date else '',
            }, request=request)
            messages.success(request, f"Case {case.case_number} created.")
            return redirect('case_public', case_number=case.case_number)
    else:
        form = CaseForm(current_user=request.user)

    return render(request, 'vault/case_form.html', {
        'form':             form,
        'mode':             'create',
        'can_edit_all':     True,
        'can_edit_status':  False,
        'can_add_evidence': False,
        'is_readonly':      False,
    })


@login_required
def case_edit(request, case_number):
    """Edit a case with role-based field restrictions."""
    case = get_object_or_404(Case, case_number=case_number)
    user = request.user

    # ---- Compute access level ----
    is_admin           = (user.role == 'ADMIN')
    is_senior_officer  = (user.role == 'OFFICER'   and user.is_senior)
    is_senior_forensic = (user.role == 'FORENSICS' and user.is_senior)
    is_junior_officer  = (user.role == 'OFFICER'   and not user.is_senior)
    is_readonly        = (user.role in ('JUDGE', 'ADVOCATE')) or \
                         (user.role == 'FORENSICS' and not user.is_senior)

    # Is this user the assigned lead officer on THIS case?
    is_lead_on_this_case = (case.lead_officer_id == user.id)

    can_edit_all     = is_admin or is_senior_officer or is_senior_forensic
    can_edit_status  = is_junior_officer

    # Junior officers who are the lead on this case can also add evidence
    can_add_evidence = (
        is_admin
        or is_senior_officer
        or is_senior_forensic
        or (is_junior_officer and is_lead_on_this_case)
    )

    if not (can_edit_all or can_edit_status or can_add_evidence):
        # Judge, advocate, junior forensic — read-only view
        pass  # allowed to see the page, cannot POST

    # ---- Handle POST ----
    if request.method == 'POST':

        # ----- Save case details -----
        if 'save_case' in request.POST:
            if is_readonly:
                raise PermissionDenied("Your role cannot edit case details.")

            # Junior officer: status only
            if can_edit_status and not can_edit_all:
                new_status = request.POST.get('status', case.status)
                if new_status in dict(Case.STATUS_CHOICES) and new_status != case.status:
                    old_status = case.get_status_display()
                    case.status = new_status
                    case.save(update_fields=['status'])
                    ledger.append(user, 'CASE_UPDATED', None, {
                        'action':     'STATUS_CHANGED',
                        'case':       case.case_number,
                        'old_status': old_status,
                        'new_status': case.get_status_display(),
                        'changed_by': user.username,
                    }, request=request)
                    messages.success(request, f"Case status updated to {case.get_status_display()}.")
                else:
                    messages.info(request, "No status change.")
                return redirect('case_edit', case_number=case.case_number)

            # Senior / admin: full edit
            form = CaseForm(request.POST, instance=case, current_user=user)
            if form.is_valid():
                case = form.save()
                ledger.append(user, 'CASE_UPDATED', None, {
                    'action': 'CASE_EDITED',
                    'case':   case.case_number,
                }, request=request)
                messages.success(request, f"Case {case.case_number} updated.")
                return redirect('case_public', case_number=case.case_number)

        # ----- Add evidence -----
        elif 'add_evidence' in request.POST:
            if not can_add_evidence:
                raise PermissionDenied("Only senior officers can add evidence to a case.")

            ev_form = InlineEvidenceForm(request.POST, request.FILES)
            form = CaseForm(instance=case, current_user=user)
            if ev_form.is_valid():
                uploaded = request.FILES['file']
                digest = ledger.hash_file(uploaded)
                uploaded.seek(0)

                new_ev = ev_form.save(commit=False)
                new_ev.case_number       = case.case_number
                new_ev.file_hash         = digest
                new_ev.file_size         = uploaded.size
                new_ev.uploaded_by       = user
                new_ev.current_custodian = user
                new_ev.save()

                ledger.append(user, 'INGEST', new_ev, {
                    'sha256':   digest,
                    'filename': os.path.basename(new_ev.file.name),
                    'size':     uploaded.size,
                    'case':     case.case_number,
                }, request=request)

                messages.success(request, f"Evidence '{new_ev.title}' added to case.")
                return redirect('case_edit', case_number=case.case_number)

    else:
        form = CaseForm(instance=case, current_user=user)
        ev_form = InlineEvidenceForm()

    existing_evidence = Evidence.objects.filter(case_number=case.case_number)

    return render(request, 'vault/case_form.html', {
        'form':              form,
        'ev_form':           ev_form,
        'mode':              'edit',
        'case':              case,
        'existing_evidence': existing_evidence,
        # Permission flags for the template
        'is_readonly':       is_readonly,
        'can_edit_all':      can_edit_all,
        'can_edit_status':   can_edit_status,
        'can_add_evidence':  can_add_evidence,
    })


@role_required('OFFICER', 'ADMIN')
def case_close(request, case_number):
    """Close a case and record the final custody disposition to the ledger."""
    case = get_object_or_404(Case, case_number=case_number)

    if case.status == 'CLOSED':
        messages.info(request, f"Case {case_number} is already closed.")
        return redirect('case_public', case_number=case_number)

    if request.method == 'POST':
        form = CaseCloseForm(request.POST)
        if form.is_valid():
            case.status           = 'CLOSED'
            case.closed_by        = request.user
            case.closed_at        = timezone.now()
            case.closing_remarks  = form.cleaned_data['closing_remarks']
            case.final_custody    = form.cleaned_data['final_custody']
            case.custody_location = form.cleaned_data['custody_location']
            case.save()

            ledger.append(request.user, 'CASE_CLOSED', None, {
                'case':             case.case_number,
                'title':            case.title,
                'closed_by':        request.user.username,
                'final_custody':    case.get_final_custody_display(),
                'custody_location': case.custody_location,
                'remarks':          case.closing_remarks[:200],
            }, request=request)

            messages.success(request, f"Case {case_number} closed.")
            return redirect('case_public', case_number=case_number)
    else:
        form = CaseCloseForm()

    return render(request, 'vault/case_close.html', {
        'case': case, 'form': form,
    })


@role_required('OFFICER', 'ADMIN')
def case_delete(request, case_number):
    """Delete a case. Only senior officers may do this."""
    if request.method != 'POST':
        return redirect('cases_list')

    if not (request.user.is_senior or request.user.role == 'ADMIN'):
        messages.error(request, "Only senior officers can delete a case.")
        return redirect('cases_list')

    if request.POST.get('confirm') != 'DELETE':
        return redirect('cases_list')

    case = Case.objects.filter(case_number=case_number).first()
    if not case:
        messages.error(request, f"Case {case_number} not found.")
        return redirect('cases_list')

    evidence_qs = Evidence.objects.filter(case_number=case_number)
    ev_ids = list(evidence_qs.values_list('id', flat=True))
    ev_count = len(ev_ids)

    block_count = LedgerEntry.objects.filter(evidence_id__in=ev_ids).count()
    LedgerEntry.objects.filter(evidence_id__in=ev_ids).delete()

    for ev in evidence_qs:
        try:
            ev.file.delete(save=False)
        except Exception:
            pass
        ev.delete()

    title = case.title
    case.delete()

    _rebuild_chain()

    messages.success(
        request,
        f"Deleted case '{title}' ({case_number}). "
        f"{ev_count} evidence item(s), {block_count} ledger block(s) removed."
    )
    return redirect('cases_list')


def case_public(request, case_number):
    try:
        case = Case.objects.get(case_number=case_number)
    except Case.DoesNotExist:
        return render(request, 'vault/case_public.html', {
            'not_found': True, 'case_number': case_number,
        })

    evidence_qs = Evidence.objects.filter(case_number=case_number)
    total = evidence_qs.count()
    sealed = evidence_qs.filter(is_sealed=True).count()
    ledger_count = LedgerEntry.objects.filter(evidence__in=evidence_qs).count()

    chain = ledger.verify_chain()
    last_entry = LedgerEntry.objects.filter(evidence__in=evidence_qs).order_by('-index').first()

    # Transfer log
    transfers = LedgerEntry.objects.filter(
        evidence__case_number=case_number,
        action__in=['TRANSFER_INITIATED', 'TRANSFER_ACCEPTED', 'TRANSFER_REJECTED'],
    ).select_related('actor', 'evidence').order_by('-timestamp')

    # Judges for the dropdown
    judges = User.objects.filter(role='JUDGE', is_active=True).order_by('first_name')

    return render(request, 'vault/case_public.html', {
        'case':         case,
        'total':        total,
        'sealed':       sealed,
        'ledger_count': ledger_count,
        'chain':        chain,
        'last_entry':   last_entry,
        'lead':         case.lead_officer,
        'senior':       case.senior_officer,
        'opened_at':    case.created_at,
        'transfers':    transfers,
        'judges':       judges,
    })


@role_required('OFFICER', 'ADMIN')
def case_seal(request, case_number):
    """Merkle-seal a case — one hash proves every file is unchanged."""
    from .merkle import compute_merkle_root

    case = get_object_or_404(Case, case_number=case_number)

    if request.method != 'POST':
        return redirect('case_public', case_number=case_number)

    evidence_qs = Evidence.objects.filter(case_number=case_number)
    if not evidence_qs.exists():
        messages.error(request, "Cannot seal a case with no evidence.")
        return redirect('case_public', case_number=case_number)

    hashes = list(evidence_qs.values_list('file_hash', flat=True))
    root = compute_merkle_root(hashes)

    case.merkle_root    = root
    case.case_sealed_at = timezone.now()
    case.case_sealed_by = request.user
    case.save()

    ledger.append(request.user, 'CASE_SEALED', None, {
        'case':           case.case_number,
        'merkle_root':    root,
        'evidence_count': len(hashes),
    }, request=request)

    messages.success(request, f"Case sealed. Merkle root: {root[:16]}…")
    return redirect('case_public', case_number=case_number)


@login_required
def case_verify_seal(request, case_number):
    """Recompute the Merkle root from current evidence and compare."""
    from .merkle import compute_merkle_root

    case = get_object_or_404(Case, case_number=case_number)

    if not case.merkle_root:
        messages.error(request, "This case has not been sealed.")
        return redirect('case_public', case_number=case_number)

    hashes = list(Evidence.objects.filter(case_number=case_number).values_list('file_hash', flat=True))
    recomputed = compute_merkle_root(hashes)

    if recomputed == case.merkle_root:
        messages.success(request, "✓ Merkle root verified. All evidence byte-identical to seal time.")
    else:
        messages.error(
            request,
            f"⚠ MERKLE MISMATCH. Expected {case.merkle_root[:16]}…, got {recomputed[:16]}…"
        )
    return redirect('case_public', case_number=case_number)


# ================================================================
# 5. OFFICER ACTIVITY (SENIOR VIEW)
# ================================================================
@login_required
def officer_activity(request):
    if not request.user.is_senior:
        raise PermissionDenied("Only senior officers can view the Officer Activity page.")

    officers = User.objects.filter(
        role__in=['OFFICER', 'FORENSICS'], is_active=True
    ).order_by('username')

    rows = []
    for o in officers:
        actions = LedgerEntry.objects.filter(actor=o)
        rows.append({
            'officer':       o,
            'in_custody':    Evidence.objects.filter(current_custodian=o).count(),
            'uploads':       Evidence.objects.filter(uploaded_by=o).count(),
            'downloads':     actions.filter(action='DOWNLOAD').count(),
            'transfers':     actions.filter(action='TRANSFER_ACCEPTED').count(),
            'total_actions': actions.count(),
            'last_action':   actions.order_by('-timestamp').first(),
        })

    recent = LedgerEntry.objects.select_related('actor', 'evidence').order_by('-index')[:80]
    cases  = Case.objects.select_related('lead_officer', 'senior_officer').order_by('-created_at')

    return render(request, 'vault/officer_activity.html', {
        'rows': rows, 'recent': recent, 'cases': cases,
    })


# ================================================================
# 6. LEDGER & VERIFICATION
# ================================================================
@login_required
def ledger_list(request):
    """Ledger — scoped to what the user is involved with."""
    user = request.user

    # Case numbers where user holds evidence
    held_case_nums = list(
        Evidence.objects.filter(current_custodian=user)
        .values_list('case_number', flat=True).distinct()
    )

    if user.role == 'ADMIN':
        entries = LedgerEntry.objects.all()
    elif user.role in ('JUDGE', 'ADVOCATE'):
        entries = LedgerEntry.objects.filter(
            Q(evidence__case_number__in=held_case_nums) |
            Q(details__case__in=held_case_nums) |
            Q(actor=user)
        )
    elif user.is_senior:
        case_nums = list(
            Case.objects.filter(
                Q(senior_officer=user) | Q(lead_officer=user)
            ).values_list('case_number', flat=True)
        )
        case_nums = list(set(case_nums + held_case_nums))
        entries = LedgerEntry.objects.filter(
            Q(evidence__case_number__in=case_nums) |
            Q(details__case__in=case_nums) |
            Q(actor=user)
        )
    else:
        case_nums = list(
            Case.objects.filter(lead_officer=user)
            .values_list('case_number', flat=True)
        )
        case_nums = list(set(case_nums + held_case_nums))
        entries = LedgerEntry.objects.filter(
            Q(evidence__case_number__in=case_nums) |
            Q(details__case__in=case_nums) |
            Q(actor=user)
        )

    entries = entries.select_related('actor', 'evidence').distinct().order_by('index')[:300]

    chain = ledger.verify_chain()

    return render(request, 'vault/ledger.html', {
        'entries': entries,
        'chain':   chain,
    })


def verify_portal(request):
    """PUBLIC — no login required."""
    result = None

    if request.method == 'POST' and request.FILES.get('file'):
        f = request.FILES['file']
        digest = ledger.hash_file(f)
        matches = list(Evidence.objects.filter(file_hash=digest))

        result = {'digest': digest, 'matches': matches, 'filename': f.name}

        ledger.append(
            request.user if request.user.is_authenticated else None,
            'VERIFY_EXTERNAL', None,
            {'digest': digest, 'matched_evidence_ids': [m.id for m in matches]},
            request=request,
        )

    return render(request, 'vault/verify.html', {'result': result})


# ================================================================
# 7. AI INSIGHTS
# ================================================================
@login_required
def ai_insights(request):
    anomalies = ai_engine.detect_anomalies()
    dist = ai_engine.risk_distribution()
    critical = ai_engine.critical_items()

    heatmap = []
    for ev in Evidence.objects.all()[:60]:
        s, level, _ = ai_engine.compute_risk_score(ev)
        heatmap.append({'ev': ev, 'score': s, 'level': level})

    stats = {
        'critical':        dist['CRITICAL'],
        'high':            dist['HIGH'],
        'medium':          dist['MEDIUM'],
        'low':             dist['LOW'],
        'anomalies':       len(anomalies),
        'high_anomalies':  sum(1 for a in anomalies if a['severity'] in ('HIGH', 'CRITICAL')),
    }

    return render(request, 'vault/ai_insights.html', {
        'anomalies': anomalies,
        'dist':      dist,
        'stats':     stats,
        'critical':  critical,
        'heatmap':   heatmap,
    })


# ================================================================
# 8. SECURITY & AUDIT
# ================================================================
@login_required
def security_dashboard(request):
    allowed = (
        request.user.role in ('ADMIN', 'FORENSICS')
        or request.user.is_senior
    )
    if not allowed:
        raise PermissionDenied("Security Center is restricted to senior officers and forensic personnel.")

    since_24h = timezone.now() - timedelta(hours=24)

    recent      = LoginAttempt.objects.all()[:50]
    failed_24h  = LoginAttempt.objects.filter(success=False, timestamp__gte=since_24h).count()
    success_24h = LoginAttempt.objects.filter(success=True,  timestamp__gte=since_24h).count()

    top_attacker_ips = (
        LoginAttempt.objects
        .filter(success=False, timestamp__gte=since_24h)
        .values('ip_address')
        .annotate(n=Count('id'))
        .order_by('-n')[:5]
    )

    tamper_events = LedgerEntry.objects.filter(action='TAMPER_ALERT')[:10]
    verify_events = LedgerEntry.objects.filter(action__startswith='VERIFY')[:10]

    chain = ledger.verify_chain()

    return render(request, 'vault/security.html', {
        'recent':         recent,
        'failed_24h':     failed_24h,
        'success_24h':    success_24h,
        'top_ips':        top_attacker_ips,
        'lockouts':       recent_lockouts(),
        'tamper_events':  tamper_events,
        'verify_events':  verify_events,
        'chain':          chain,
        'ai_anomalies':   ai_engine.detect_anomalies()[:8],
    })


def canary(request):
    """Honeypot endpoint — any hit logs a TAMPER_ALERT."""
    ledger.append(
        request.user if request.user.is_authenticated else None,
        'TAMPER_ALERT', None,
        {'canary': 'INTERNAL_DEBUG_ENDPOINT', 'context': 'Honeypot triggered',
         'path': request.path, 'method': request.method},
        request=request,
    )
    return HttpResponseForbidden("Access denied. This event has been logged to the ledger.")


# ================================================================
# 9. ANALYTICS
# ================================================================
@login_required
def analytics(request):
    by_category = list(Evidence.objects.values('category').annotate(n=Count('id')).order_by('-n'))
    by_sensitivity = list(Evidence.objects.values('sensitivity').annotate(n=Count('id')).order_by('-n'))
    actions = list(LedgerEntry.objects.values('action').annotate(n=Count('id')).order_by('-n'))
    custodies = list(Evidence.objects.values('current_custodian__username')
                     .annotate(n=Count('id')).order_by('-n')[:8])

    growth_labels, growth_values = [], []
    today = timezone.now().date()
    running = 0
    for i in range(29, -1, -1):
        day = today - timedelta(days=i)
        n = LedgerEntry.objects.filter(timestamp__date=day).count()
        running += n
        growth_labels.append(day.strftime('%b %d'))
        growth_values.append(running)

    return render(request, 'vault/analytics.html', {
        'cat_labels':    [c['category'] for c in by_category],
        'cat_values':    [c['n'] for c in by_category],
        'sens_labels':   [s['sensitivity'] for s in by_sensitivity],
        'sens_values':   [s['n'] for s in by_sensitivity],
        'action_labels': [a['action'] for a in actions],
        'action_values': [a['n'] for a in actions],
        'custody_labels': [c['current_custodian__username'] or '—' for c in custodies],
        'custody_values': [c['n'] for c in custodies],
        'growth_labels': growth_labels,
        'growth_values': growth_values,
        'total_evidence': Evidence.objects.count(),
        'total_blocks':   LedgerEntry.objects.count(),
        'total_cases':    Case.objects.count(),
    })


# ================================================================
# 10. EVIDENCE GRAPH
# ================================================================
@login_required
def evidence_graph(request):
    """Evidence graph — scoped by what the user can see."""
    from django.db.models import Q

    user = request.user

    # Scope: admin/judge/advocate see all; everyone else sees what they hold or are involved in
    if user.role == 'ADMIN':
        evidence_qs = Evidence.objects.all()
    elif user.role in ('JUDGE', 'ADVOCATE'):
        evidence_qs = Evidence.objects.filter(current_custodian=user)
    else:
        case_nums = list(
            Case.objects.filter(
                Q(senior_officer=user) | Q(lead_officer=user)
            ).values_list('case_number', flat=True)
        )
        evidence_qs = Evidence.objects.filter(
            Q(current_custodian=user) |
            Q(uploaded_by=user) |
            Q(case_number__in=case_nums)
        ).distinct()

    evidence_qs = evidence_qs.select_related('uploaded_by', 'current_custodian')[:200]

    nodes = []
    edges = []
    case_set = set()
    officer_map = {}

    for ev in evidence_qs:
        nodes.append({
            'id':    f'ev_{ev.id}',
            'label': ev.title[:24],
            'group': 'evidence',
            'title': f"{ev.title}\nCase {ev.case_number}\nSHA-256: {ev.file_hash[:16]}…",
        })

        cid = f'case_{ev.case_number}'
        if ev.case_number not in case_set:
            case_set.add(ev.case_number)
            nodes.append({
                'id':    cid,
                'label': ev.case_number,
                'group': 'case',
                'title': f"Case {ev.case_number}",
            })
        edges.append({'from': f'ev_{ev.id}', 'to': cid})

        u = ev.uploaded_by
        if u:
            uid = f'user_{u.id}'
            if u.id not in officer_map:
                officer_map[u.id] = True
                nodes.append({
                    'id':    uid,
                    'label': u.get_full_name() or u.username,
                    'group': 'officer',
                    'title': f"{u.get_full_name() or u.username}\n{u.get_role_display()}",
                })
            edges.append({'from': uid, 'to': f'ev_{ev.id}', 'label': 'uploaded'})

        c = ev.current_custodian
        if c and c.id != (u.id if u else None):
            cid2 = f'user_{c.id}'
            if c.id not in officer_map:
                officer_map[c.id] = True
                nodes.append({
                    'id':    cid2,
                    'label': c.get_full_name() or c.username,
                    'group': 'officer',
                    'title': f"{c.get_full_name() or c.username}\n{c.get_role_display()}",
                })
            edges.append({'from': cid2, 'to': f'ev_{ev.id}', 'label': 'custody'})

    return render(request, 'vault/evidence_graph.html', {
        'nodes_json': json.dumps(nodes),
        'edges_json': json.dumps(edges),
    })

# ================================================================
# 11. PROFILE & ACCOUNT
# ================================================================
@login_required
def profile(request):
    user = request.user

    evidence_uploaded   = Evidence.objects.filter(uploaded_by=user).count()
    evidence_in_custody = Evidence.objects.filter(current_custodian=user).count()
    sealed_count        = Evidence.objects.filter(current_custodian=user, is_sealed=True).count()
    ledger_actions      = LedgerEntry.objects.filter(actor=user).count()

    recent_activity = (
        LedgerEntry.objects
        .filter(actor=user)
        .select_related('evidence')
        .order_by('-index')[:15]
    )

    held_total = Evidence.objects.filter(current_custodian=user).count()

    failed_logins = LoginAttempt.objects.filter(username=user.username, success=False).count()

    return render(request, 'vault/profile.html', {
        'profile_user':        user,
        'evidence_uploaded':   evidence_uploaded,
        'evidence_in_custody': evidence_in_custody,
        'sealed_count':        sealed_count,
        'ledger_actions':      ledger_actions,
        'recent_activity':     recent_activity,
        'can_deactivate':      held_total == 0,
        'held_unsealed':       held_total,
        'failed_logins':       failed_logins,
    })


@login_required
def delete_account(request):
    """Permanently delete the account, its evidence, and its login history."""
    if request.method != 'POST':
        return redirect('profile')

    user = request.user

    if request.POST.get('confirm', '').strip() != 'DELETE':
        messages.error(request, "You must type DELETE in the confirmation box.")
        return redirect('profile')

    if user.role == 'ADMIN':
        remaining = User.objects.filter(role='ADMIN', is_active=True).exclude(pk=user.pk).count()
        if remaining == 0:
            messages.error(request, "Cannot delete the last active administrator.")
            return redirect('profile')

    username  = user.username
    full_name = user.get_full_name() or username

    owned_evidence_ids = list(
        Evidence.objects.filter(
            Q(uploaded_by=user) | Q(current_custodian=user) | Q(sealed_by=user)
        ).values_list('id', flat=True)
    )

    logout(request)

    LedgerEntry.objects.filter(
        Q(actor=user) | Q(evidence_id__in=owned_evidence_ids)
    ).delete()

    for ev in Evidence.objects.filter(id__in=owned_evidence_ids):
        try:
            ev.file.delete(save=False)
        except Exception:
            pass
        ev.delete()

    LoginAttempt.objects.filter(username=username).delete()
    User.objects.filter(username='__deleted__').delete()
    User.objects.filter(username__startswith='archived_').delete()

    user.delete()
    _rebuild_chain()

    messages.success(
        request,
        f"Account '{full_name}' ({username}) permanently deleted."
    )
    return redirect('home')


# ================================================================
# 12. REPORTS & COURT PACKAGE
# ================================================================
@login_required
def evidence_report(request, pk):
    """Printable court report."""
    ev = get_object_or_404(Evidence, pk=pk)
    entries = ev.ledger_entries.select_related('actor').order_by('index')
    file_check = ledger.verify_evidence_file(ev)
    chain = ledger.verify_chain()

    ledger.append(request.user, 'VIEW', ev, {'context': 'Generated court report'},
                  request=request)

    return render(request, 'vault/report.html', {
        'ev': ev, 'entries': entries,
        'file_check': file_check, 'chain': chain,
        'now': timezone.now(),
    })


@login_required
def evidence_court_package(request, pk):
    """Download a ZIP containing original + custody report + manifest."""
    ev = get_object_or_404(Evidence, pk=pk)

    check = ledger.verify_evidence_file(ev)
    if not check['ok']:
        ledger.append(request.user, 'TAMPER_ALERT', ev, {
            'expected': check.get('expected', ''),
            'actual':   check.get('actual', ''),
            'context':  'Detected during court package generation',
        }, request=request)
        return HttpResponseForbidden("Integrity check failed. Court package blocked.")

    entries = ev.ledger_entries.select_related('actor').order_by('index')
    chain = ledger.verify_chain()

    entry = ledger.append(request.user, 'DOWNLOAD', ev, {
        'sha256':   ev.file_hash,
        'filename': os.path.basename(ev.file.name),
        'context':  'Court package download',
    }, request=request)

    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        with ev.file.open('rb') as f:
            original_bytes = f.read()
        original_name = os.path.basename(ev.file.name)
        zf.writestr(f'original/{original_name}', original_bytes)

        manifest = (
            "CaseVault Court Package\n"
            "========================\n\n"
            f"Case Number       : {ev.case_number}\n"
            f"Evidence Title    : {ev.title}\n"
            f"Category          : {ev.get_category_display()}\n"
            f"Classification    : {ev.get_sensitivity_display()}\n"
            f"Warrant           : {ev.warrant_number or 'N/A'}\n\n"
            f"Original File     : {original_name}\n"
            f"File Size         : {ev.file_size} bytes\n"
            f"SHA-256           : {ev.file_hash}\n\n"
            f"Ingested By       : {ev.uploaded_by.username}\n"
            f"Ingested At       : {ev.created_at.isoformat()}\n"
            f"Current Custodian : {ev.current_custodian.username}\n\n"
            f"Chain Integrity   : {'VERIFIED' if chain['ok'] else 'BROKEN'}\n"
            f"Ledger Blocks     : {chain.get('length', 0)}\n\n"
            f"Package Generated : {timezone.now().isoformat()}\n"
            f"Generated By      : {request.user.username}\n"
            f"Ledger Index      : {entry.index}\n"
            f"Ledger Block Hash : {entry.entry_hash}\n"
        )
        zf.writestr('MANIFEST.txt', manifest)

        report_html = render_to_string('vault/court_package_report.html', {
            'ev': ev, 'entries': entries, 'chain': chain,
            'file_check': check, 'now': timezone.now(),
            'entry': entry, 'generator': request.user,
        })
        zf.writestr('custody_report.html', report_html)

    buf.seek(0)
    safe_title = ev.title.replace(' ', '_').replace('/', '-')[:40]
    zip_name = f'casevault_{ev.case_number}_{safe_title}.zip'

    resp = HttpResponse(buf.getvalue(), content_type='application/zip')
    resp['Content-Disposition'] = f'attachment; filename="{zip_name}"'
    resp['X-CaseVault-SHA256'] = ev.file_hash
    return resp


# ================================================================
# 13. UTILITY — CHAIN REBUILD
# ================================================================
def _rebuild_chain():
    """Re-link the remaining ledger entries so verify_chain() passes again."""
    from .ledger import sha256_hex, canonical_payload, GENESIS_HASH

    entries = list(LedgerEntry.objects.order_by('index'))
    if not entries:
        return

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

@login_required
def case_send_to_judge(request, case_number):
    """Send the entire case (all evidence) to a specific judge. Only judges allowed."""
    case = get_object_or_404(Case, case_number=case_number)
    user = request.user

    # Only senior officers / lead officer / admin can send to a judge
    allowed = (
        user.role == 'ADMIN'
        or user.is_senior
        or case.lead_officer_id == user.id
    )
    if not allowed:
        raise PermissionDenied("Only senior officers can send a case to a judge.")

    if request.method == 'POST':
        judge_id = request.POST.get('judge_id')
        if not judge_id:
            messages.error(request, "Please select a judge.")
            return redirect('case_public', case_number=case_number)

        judge = User.objects.filter(pk=judge_id, role='JUDGE', is_active=True).first()
        if not judge:
            messages.error(request, "Invalid judge selected.")
            return redirect('case_public', case_number=case_number)

        # Send every piece of evidence to the judge
        evidence_qs = Evidence.objects.filter(case_number=case_number)
        count = 0
        for ev in evidence_qs:
            if ev.current_custodian_id == judge.id:
                continue
            block = ledger.append(user, 'TRANSFER_INITIATED', ev, {
                'from':   ev.current_custodian.username,
                'to':     judge.username,
                'reason': f'Case {case_number} submitted for judicial review',
                'status': 'PENDING',
            }, request=request)
            PendingTransfer.objects.create(
                evidence=ev,
                from_user=ev.current_custodian,
                to_user=judge,
                reason=f'Case {case_number} submitted for judicial review',
                initiate_block=block,
            )
            count += 1

        if count:
            messages.success(
                request,
                f"Case sent to {judge.get_full_name() or judge.username}. "
                f"{count} evidence item(s) awaiting their countersignature."
            )
        else:
            messages.info(request, f"{judge.username} already holds all evidence in this case.")

        return redirect('case_public', case_number=case_number)

    return redirect('case_public', case_number=case_number)

@login_required
def tamper_demo(request):
    """DEMO TOOL — Simulate ledger tampering through the web UI."""
    from django.utils import timezone as tz

    if request.method == 'POST':
        action = request.POST.get('action')
        block_index = request.POST.get('index')

        if action == 'restore_all':
            count = 0
            affected_cases = set()
            for e in LedgerEntry.objects.all():
                if e.details and e.details.get('TAMPERED'):
                    new_details = dict(e.details)
                    new_details.pop('TAMPERED', None)
                    new_details.pop('TAMPERED_NOTE', None)
                    new_details.pop('TAMPERED_AT', None)
                    e.details = new_details
                    e.save(update_fields=['details'])
                    if e.evidence:
                        affected_cases.add(e.evidence.case_number)
                    count += 1
            # Clear tamper notifications for restored cases
            if affected_cases:
                from .models import Notification
                Notification.objects.filter(
                    action='TAMPER_ALERT',
                    case_number__in=affected_cases,
                ).delete()
            if count:
                messages.success(request, f"Restored {count} tampered block(s). Chain VERIFIED. Tamper alerts cleared.")
            else:
                messages.info(request, "No tampered blocks to restore.")
            return redirect('tamper_demo')

        entry = LedgerEntry.objects.filter(index=block_index).first()
        if not entry:
            messages.error(request, f"Block #{block_index} not found.")
            return redirect('tamper_demo')

        if action == 'tamper':
            new_details = dict(entry.details or {})
            new_details['TAMPERED'] = True
            new_details['TAMPERED_NOTE'] = 'Simulated data tampering — modified after chain creation'
            new_details['TAMPERED_AT'] = tz.now().isoformat()
            entry.details = new_details
            entry.save(update_fields=['details'])

            # Notify every assigned party that this evidence was tampered with
            if entry.evidence:
                from .notifications import notify_tamper
                notify_tamper(entry.evidence, request.user, entry.index)

            messages.warning(
                request,
                f"Block #{entry.index} tampered. Check the ledger — the chain should now show BROKEN."
            )
        elif action == 'restore':
            new_details = dict(entry.details or {})
            new_details.pop('TAMPERED', None)
            new_details.pop('TAMPERED_NOTE', None)
            new_details.pop('TAMPERED_AT', None)
            entry.details = new_details
            entry.save(update_fields=['details'])

            # Clear tamper alerts for this evidence's case
            if entry.evidence:
                from .models import Notification
                Notification.objects.filter(
                    action='TAMPER_ALERT',
                    case_number=entry.evidence.case_number,
                ).delete()

            messages.success(request, f"Block #{entry.index} restored. Chain VERIFIED. Tamper alerts cleared.")

        return redirect('tamper_demo')

    entries = LedgerEntry.objects.order_by('-index')[:20]
    chain = ledger.verify_chain()
    tampered_count = sum(
        1 for e in LedgerEntry.objects.all()
        if e.details and e.details.get('TAMPERED')
    )

    return render(request, 'vault/tamper_demo.html', {
        'entries':        entries,
        'chain':          chain,
        'tampered_count': tampered_count,
    })

@login_required
def clear_notifications(request):
    request.user.notifications.all().delete()
    messages.success(request, "Notifications cleared.")
    return redirect(request.META.get('HTTP_REFERER', 'dashboard'))