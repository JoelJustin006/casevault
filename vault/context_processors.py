def notifications(request):
    if not request.user.is_authenticated:
        return {}
    qs = request.user.notifications.all()[:10]
    unread = request.user.notifications.filter(read=False).count()
    return {
        'recent_notifications': qs,
        'unread_notifications': unread,
    }