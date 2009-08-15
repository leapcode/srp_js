# Locally used functions: 
def join(a,b):
    return a+b if a.endswith("/") else "/".join((a,b))

def genHeader(jsDir, flist):
    return "\n".join(["<script src='%s'></script>" % join(jsDir, f) for f in flist])

# Headers:
def loginHeader(jsDir, compressed=True):
    return genHeader(jsDir, ["srp.min.js"] if compressed else ["SHA256.js", "prng4.js", "rng.js", "jsbn.js", "jsbn2.js", "srp.js"])

def registerHeader(jsDir, compressed=True):
    return genHeader(jsDir, ["srp.min.js", "srp_register.min.js"] if compressed else \
["SHA256.js", "prng4.js", "rng.js", "jsbn.js", "jsbn2.js", "srp.js", "srp_register.js"])

# Forms:
def loginForm(srp_url, srp_forward, login_function="login()", no_js=True):
    return """<form action="%s" method="POST" onsubmit="return %s">
<table>
<tr><td>Username:</td><td><input type="text" name="srp_username" id="srp_username" /></td></tr>
<tr><td>Password:</td><td><input type="password" name="srp_password" id="srp_password" /></td></tr>
<input type="hidden" id="srp_url" value="%s"/>
<input type="hidden" name="srp_forward" id="srp_forward" value="%s"/>
<input type="hidden" id="srp_server" value="django"/>
</table>
<input type="submit"/>
</form>""" % (join(srp_url, "noJs/") if no_js else "#", login_function, join(srp_url, ""), srp_forward)

def registerForm(srp_url, srp_forward, login_function="register()"):
    return """<form action="#" method="POST" onsubmit="return %s">
<table>
<tr><td>Username:</td><td><input type="text" name="srp_username" id="srp_username" /></td></tr>
<tr><td>Password:</td><td><input type="password" name="srp_password" id="srp_password" /></td></tr>
<tr><td>Confirm Password:</td><td><input type="password" id="confirm_password" /></td></tr>
<input type="hidden" id="srp_url" value="%s"/>
<input type="hidden" name="srp_forward" id="srp_forward" value="%s"/>
<input type="hidden" id="srp_server" value="django"/>
</table>
<input type="submit"/>
</form>""" % (login_function, join(srp_url, ""), srp_forward)


# Functions: 
def loginFunction():
    return """<script type="text/javascript">
function login()
{
    srp = new SRP();
    srp.identify();
    return false;
}
</script>"""

def registerFunction():
    return """<script type="text/javascript">function register()
{
    if(document.getElementById("confirm_password").value != document.getElementById("srp_password").value)
        alert("Passwords do not match");
    else if(document.getElementById("srp_password").value == "")
        alert("Password cannot be blank");
    else
    {
        srp = new SRP();
        srp.register();
    }
    return false;
};</script>"""
