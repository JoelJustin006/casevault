from .models import Case, Notification, User


def notify_senior(case_number, actor, action, message):
    """Send a notification to the senior officer of a case, with the actor's name."""
    if not case_number:
        return
    case = Case.objects.filter(case_number=case_number).first()
    if not case or not case.senior_officer:
        return

    actor_name = actor.get_full_name() or actor.username if actor else 'System'
    full_message = f"{actor_name} {message}"

    Notification.objects.create(
        recipient=case.senior_officer,
        actor=actor,
        case_number=case_number,
        action=action,
        message=full_message,
    )

def notify_tamper(evidence, actor, block_index):
    """Notify every assigned party that a ledger block was tampered."""
    from .models import Case, Notification, PendingTransfer, User

    recipients = set()

    # 1. Case team — lead officer + senior officer
    case = Case.objects.filter(case_number=evidence.case_number).first()
    if case:
        if case.lead_officer_id:
            recipients.add(case.lead_officer_id)
        if case.senior_officer_id:
            recipients.add(case.senior_officer_id)

    # 2. Current custodian of this evidence
    if evidence.current_custodian_id:
        recipients.add(evidence.current_custodian_id)

    # 3. Everyone who has ever been a transfer party for this evidence
    for t in PendingTransfer.objects.filter(evidence=evidence):
        if t.from_user_id:
            recipients.add(t.from_user_id)
        if t.to_user_id:
            recipients.add(t.to_user_id)

    # 4. Original uploader
    if evidence.uploaded_by_id:
        recipients.add(evidence.uploaded_by_id)

    # Don't notify the actor who triggered the tamper
    if actor and actor.id:
        recipients.discard(actor.id)

    message = (
        f"⚠ TAMPER ALERT: Ledger block #{block_index} has been tampered. "
        f"Evidence '{evidence.title}' (case {evidence.case_number}) may be compromised. "
        f"Immediate review required."
    )

    for uid in recipients:
        Notification.objects.create(
            recipient_id=uid,
            actor=actor,
            case_number=evidence.case_number,
            action='TAMPER_ALERT',
            message=message,
        )