from django.conf.urls.defaults import *

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()
import srp.views

urlpatterns = patterns('',

    # Login and regiser pages. These are mainly for testing.
    (r'^srp/register/$', srp.views.register_page),
    (r'^srp/login/$', srp.views.login_page),

    # These pages are necessary for users to register
    (r'^srp/register/salt/$', srp.views.register_salt),
    (r'^srp/register/user/$', srp.views.register_user),

    # These pages are necessary for users to log in
    (r'^srp/handshake/$', srp.views.handshake),
    (r'^srp/authenticate/$', srp.views.verify),

    # This page allows users to login without javascript, 
    # but the browser posts their username and password in plaintext.
    (r'^srp/noJs/$', srp.views.no_javascript),

    # Only include these if you are upgrading an existing installation to SRP
    (r'^srp/upgrade/authenticate/$', srp.views.upgrade_auth),
    (r'^srp/upgrade/verifier/$', srp.views.upgrade_add_verifier),
)
