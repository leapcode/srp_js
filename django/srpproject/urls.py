from django.conf.urls.defaults import *

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()
from srpproject.srp import views

urlpatterns = patterns('',
    # Example:
    # (r'^srpproject/', include('srpproject.foo.urls')),

    # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # (r'^admin/(.*)', admin.site.root),

    # Login and regiser pages. These are mainly for testing.
    (r'^srp/register/$', views.register_page),
    (r'^srp/login/$', views.login_page),

    (r'^srp/register/salt/$', views.register_salt),
    (r'^srp/register/user/$', views.register_user),

    # 
    (r'^srp/handshake/$', views.handshake),
    (r'^srp/authenticate/$', views.verify),

    # Only include these if you are upgrading an existing installation to SRP
    (r'^srp/upgrade/authenticate/$', views.upgrade_auth),
    (r'^srp/upgrade/verifier/$', views.upgrade_add_verifier),
)
