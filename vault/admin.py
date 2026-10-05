from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Evidence, LedgerEntry
from .models import Case

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (('CaseVault', {'fields': ('role', 'badge_id')}),)
    list_display = ('username', 'role', 'badge_id', 'is_staff')


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
    list_display = ('case_number', 'title', 'short_hash', 'uploaded_by', 'current_custodian', 'created_at')
    search_fields = ('case_number', 'title', 'file_hash')
    readonly_fields = ('file_hash', 'file_size', 'created_at')


@admin.register(LedgerEntry)
class LedgerAdmin(admin.ModelAdmin):
    list_display = ('index', 'timestamp', 'action', 'actor', 'evidence', 'entry_hash')
    readonly_fields = [f.name for f in LedgerEntry._meta.fields]

    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False
    def has_delete_permission(self, request, obj=None): return False

from .models import LoginAttempt

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'username', 'ip_address', 'success')
    list_filter = ('success', 'timestamp')
    search_fields = ('username', 'ip_address')
    readonly_fields = [f.name for f in LoginAttempt._meta.fields]

    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False

@admin.register(Case)
class CaseAdmin(admin.ModelAdmin):
    list_display  = ('case_number', 'title', 'status', 'lead_officer', 'court_date', 'created_at')
    list_filter   = ('status',)
    search_fields = ('case_number', 'title', 'prosecutor')