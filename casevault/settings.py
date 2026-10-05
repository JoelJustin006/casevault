from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get(
    'DJANGO_SECRET_KEY',
    'django-insecure-dev-only-key-change-this-in-production'
)
DEBUG = True
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'vault.apps.VaultConfig',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'vault.middleware.SecurityHeadersMiddleware',
    'vault.auto_seed.AutoSeedMiddleware',          # ← ADD THIS LINE
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'casevault.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'vault.context_processors.notifications',
            ],
        },
    },
]

WSGI_APPLICATION = 'casevault.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ----- CaseVault -----
AUTH_USER_MODEL = 'vault.User'

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'dashboard'
LOGOUT_REDIRECT_URL = 'home'

FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024

# ----- Security hardening -----
SESSION_COOKIE_HTTPONLY      = True
SESSION_COOKIE_SAMESITE      = 'Lax'
CSRF_COOKIE_HTTPONLY         = False   # needs to be readable by form JS in some setups
SECURE_CONTENT_TYPE_NOSNIFF  = True
SECURE_BROWSER_XSS_FILTER    = True
X_FRAME_OPTIONS              = 'DENY'
SESSION_COOKIE_AGE           = 60 * 60 * 8   # 8-hour shift
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST   = True          # sliding expiry while active

# ----- Auto-seed control -----
# Set the env var CASEVAULT_AUTO_SEED=1 to auto-populate demo data.
# Leave unset for a clean install — register your own users.
import os as _os
AUTO_SEED_ENABLED = _os.environ.get('CASEVAULT_AUTO_SEED', '0') == '1'