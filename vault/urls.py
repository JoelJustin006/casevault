from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # Public
    path('',                views.home,           name='home'),
    path('verify/',         views.verify_portal,  name='verify_portal'),
    path('case/<str:case_number>/', views.case_public, name='case_public'),
    path('login/',          views.AuditedLoginView.as_view(), name='login'),
    path('logout/',         auth_views.LogoutView.as_view(),  name='logout'),
    path('register/',       views.register,       name='register'),

    # Authenticated
    path('dashboard/',      views.dashboard,      name='dashboard'),
    path('analytics/',      views.analytics,      name='analytics'),

    path('evidence/upload/',   views.evidence_upload,  name='evidence_upload'),
    path('evidence/<int:pk>/', views.evidence_detail,  name='evidence_detail'),
    path('evidence/<int:pk>/download/', views.evidence_download, name='evidence_download'),
    path('evidence/<int:pk>/transfer/', views.evidence_transfer, name='evidence_transfer'),
    path('evidence/<int:pk>/seal/',     views.evidence_seal,     name='evidence_seal'),
    path('evidence/<int:pk>/report/',   views.evidence_report,   name='evidence_report'),

    path('ledger/',         views.ledger_list,        name='ledger_list'),
    path('security/',       views.security_dashboard, name='security_dashboard'),

    path('profile/', views.profile, name='profile'),
    path('profile/deactivate/', views.delete_account, name='delete_account'),

    path('ai/', views.ai_insights, name='ai_insights'),
    path('vault-internal/heartbeat/', views.canary, name='canary'),

    path('evidence/<int:pk>/court-package/', views.evidence_court_package, name='evidence_court_package'),

    path('evidence/<int:pk>/delete/', views.evidence_delete, name='evidence_delete'),

    path('cases/',                          views.cases_list,   name='cases_list'),
    path('cases/create/',                   views.case_create,  name='case_create'),
    path('cases/<str:case_number>/edit/',   views.case_edit,    name='case_edit'),
    path('cases/<str:case_number>/delete/', views.case_delete,  name='case_delete'),

    path('officers/', views.officer_activity, name='officer_activity'),

    path('cases/<str:case_number>/close/', views.case_close, name='case_close'),

    path('actions/', views.pending_actions, name='pending_actions'),
    path('transfer/<int:pk>/accept/', views.transfer_accept, name='transfer_accept'),
    path('transfer/<int:pk>/reject/', views.transfer_reject, name='transfer_reject'),

    path('cases/<str:case_number>/seal/',        views.case_seal,        name='case_seal'),
    path('cases/<str:case_number>/verify-seal/', views.case_verify_seal, name='case_verify_seal'),

    path('graph/', views.evidence_graph, name='evidence_graph'),

    path('cases/<str:case_number>/send-to-judge/', views.case_send_to_judge, name='case_send_to_judge'),

    path('demo/tamper/', views.tamper_demo, name='tamper_demo'),

    path('notifications/clear/', views.clear_notifications, name='clear_notifications'),
]