from functools import wraps
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied


def role_required(*roles):
    def deco(view):
        @wraps(view)
        @login_required
        def wrapper(request, *args, **kwargs):
            if request.user.role not in roles:
                raise PermissionDenied(
                    f"Your role ({request.user.get_role_display()}) cannot perform this action."
                )
            return view(request, *args, **kwargs)
        return wrapper
    return deco