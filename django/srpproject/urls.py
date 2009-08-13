from django.conf.urls.defaults import *

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()
from srpproject.srp import views

urlpatterns = patterns('',

    # Login and regiser pages. These are mainly for testing.
    (r'^srp/register/$', views.register_page),
    (r'^srp/login/$', views.login_page),

    # These pages are necessary for users to register
    (r'^srp/register/salt/$', views.register_salt),
    (r'^srp/register/user/$', views.register_user),

    # These pages are necessary for users to log in
    (r'^srp/handshake/$', views.handshake),
    (r'^srp/authenticate/$', views.verify),

    # This page allows users to login without javascript, 
    # but the browser posts their username and password in plaintext.
    (r'^srp/noJs/$', views.no_javascript),

    # Only include these if you are upgrading an existing installation to SRP
    (r'^srp/upgrade/authenticate/$', views.upgrade_auth),
    (r'^srp/upgrade/verifier/$', views.upgrade_add_verifier),
)
