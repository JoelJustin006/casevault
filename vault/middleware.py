"""Security headers middleware — CSP, XFO, HSTS, Referrer-Policy, Permissions-Policy."""


class SecurityHeadersMiddleware:
    """
    Adds defense-in-depth HTTP headers to every response.
    Tuned to allow Bootstrap + Google Fonts + Bootstrap Icons CDNs.
    """

    CSP = (
    "default-src 'self'; "
    "style-src 'self' 'unsafe-inline' "
    "https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: blob:; "
    "connect-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self';"
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        response['Content-Security-Policy'] = self.CSP
        response['X-Content-Type-Options']    = 'nosniff'
        response['X-Frame-Options']           = 'DENY'
        response['Referrer-Policy']           = 'strict-origin-when-cross-origin'
        response['Permissions-Policy']        = 'geolocation=(), microphone=(), camera=(), payment=()'
        response['Cross-Origin-Opener-Policy'] = 'same-origin'
        response['Cross-Origin-Resource-Policy'] = 'same-origin'

        # HSTS only meaningful when served over HTTPS; harmless in dev since
        # browsers ignore it on http:// origins.
        if request.is_secure():
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        return response