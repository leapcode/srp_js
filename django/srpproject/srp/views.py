# Create your views here.

from django.http import HttpResponse

from srp import models

###
### General methods
###

# We need randomly generated salts. This is about 100 bits of entropy.
def generate_salt():
    import string, random   
    randomgen = random.SystemRandom()
    salt_chars = "./" + string.ascii_letters + string.digits
    return "".join([randomgen.choice(salt_chars) for i in range(0,16)])

# We want to avoid information leakage. For users that don't exist, we need salts to be consistent.
# These "fake" salts are seeded with the username and the django secret_key. They're not as random
# as true salts should be, but they should be indistinguishable to a hacker who isn't sure whether
# or not an account exists.
def generate_fake_salt(I):
    import string, random, settings, hashlib
    random.seed("%s:%s" % (I, settings.SECRET_KEY))
    salt_chars = "./" + string.ascii_letters + string.digits    
    salt = "".join([random.choice(salt_chars) for i in range(0,16)])
    return salt, int(hashlib.sha256("%s:%s" % (salt, settings.SECRET_KEY)).hexdigest(), 16)
    
def login_page(request):
    return HttpResponse("""<html>
 <head>
    <script src="http://%s/srp-test/javascript/SHA256.js"></script>
    <script src="http://%s/srp-test/javascript/prng4.js"></script>
    <script src="http://%s/srp-test/javascript/rng.js"></script>
    <script src="http://%s/srp-test/javascript/jsbn.js"></script>
    <script src="http://%s/srp-test/javascript/jsbn2.js"></script>
    <script src="http://%s/srp-test/javascript/srp.js"></script>
    <script type="text/javascript">
        function srp_success()
        {
            alert("Authentication successful.");
        }
    </script>
 </head>
 <body>
    <form action="." onsubmit="return srp_identify()">
    <table>
    <tr><td>Username:</td><td><input type="text" id="srp_username" /></td></tr>
    <tr><td>Password:</td><td><input type="password" id="srp_password" /></td></tr>
    </table>
    <input type="submit"/>
    </form>
 </body>
</html>""" % (request.get_host(), request.get_host(), request.get_host(),request.get_host(), request.get_host(), request.get_host()))

def register_page(request):
    return HttpResponse("""<html>
 <head>
    <script src="http://%s/srp-test/javascript/SHA256.js"></script>
    <script src="http://%s/srp-test/javascript/prng4.js"></script>
    <script src="http://%s/srp-test/javascript/rng.js"></script>
    <script src="http://%s/srp-test/javascript/jsbn.js"></script>
    <script src="http://%s/srp-test/javascript/jsbn2.js"></script>
    <script src="http://%s/srp-test/javascript/srp.js"></script>
    <script type="text/javascript">
function register()
{
    if(document.getElementById("confirm_password").value != document.getElementById("srp_password").value)
        alert("Passwords do not match");
    else if(document.getElementById("srp_password").value == "")
        alert("Password cannot be blank");
    else
        srp_register();
    return false;
};
function srp_success()
{
    alert("Authentication successful.");
};
    </script>
 </head>
 <body>
    <form action="." onsubmit="return register()">
    <table>
    <tr><td>Username:</td><td><input type="text" id="srp_username" /></td></tr>
    <tr><td>Password:</td><td><input type="password" id="srp_password" /></td></tr>
    <tr><td>Confirm:</td><td><input type="password" id="confirm_password" /></td></tr>
    </table>
    <input type="submit"/>
    </form>
 </body>
</html>""" % (request.get_host(), request.get_host(), request.get_host(),request.get_host(), request.get_host(), request.get_host()))

###
### User Registration
###

# Step 1. A client submits a username. If the username is available, we generate a salt, store it, and return it.
# Otherwise, we return an error.
def register_salt(request):
    if models.User.objects.filter(name=request.POST["I"]).count() > 0:
        return HttpResponse("<error>Username already in use</error>", mimetype="text/xml")
    request.session["srp_name"] = request.POST["I"]
    request.session["srp_salt"] = generate_salt()
    return HttpResponse("<salt>%s</salt>" % request.session["srp_salt"], mimetype="text/xml")
    
# Step 2. The client creates the password verifier and sends it to the server, along with a username.
def register_user(request):
    from django.contrib import auth
    models.User(salt=request.session["srp_salt"], name=request.session["srp_name"], verifier=request.POST["v"]).save()
    auth.models.User.objects.create_user(request.session["srp_name"],'', str(request.POST["v"]))
    del request.session["srp_salt"]
    del request.session["srp_name"]
    return HttpResponse("<ok/>", mimetype="text/xml");
    
# Step 3: The client initiates the login process.

###
### User Login
###

# Step 1: The user sends an identifier and public ephemeral key, A
# The server responds with the salt and public ephemeral key, B
def handshake(request):
    import random, hashlib
    randomgen = random.SystemRandom()
    request.session["srp_I"] = request.POST["I"]
    A = int(request.POST["A"], 16)
    request.session["srp_A"] = request.POST["A"]
    g = 2
    N = 125617018995153554710546479714086468244499594888726646874671447258204721048803
    k = 88846390364205216646376352624313659232912717719075174937149043299744712465496
    if A % N == 0:
        return HttpResponse("<error>Invalid ephemeral key.</error>", mimetype="text/xml")
    else:
        try:
            user = models.User.objects.get(name=request.session["srp_I"])
            salt = user.salt
            v = int(user.verifier, 16)
        # We don't want to leak that the username doesn't exist. Make up a fake salt and verifier.
        except models.User.DoesNotExist:
            salt, x = generate_fake_salt(request.POST["I"])
            v = pow(g, x, N)
            
        request.session["srp_v"] = hex(v)[2:-1]

        # Ensure that B%N != 0
        while True:
            b = randomgen.getrandbits(32)
            B = k*v + pow(g,b,N)
            u =  int(hashlib.sha256("%s%s" % (hex(A)[2:-1],hex(B)[2:-1])).hexdigest(), 16)
            if B % N != 0 and u % N != 0: break

        response = "<r s='%s' B='%s' />" % (salt, hex(B)[2:-1])
        # Ideally, we could return this response and then calculate M concurrently with the user
        # Unfortunately, django isn't designed to do computations after responding.
        # Maybe someone will find a way.
        S = pow(A*pow(v,u,N), b, N)
        request.session["srp_S"] = hex(S)[2:-1]
        Mstr = "%s%s%s" % (hex(A)[2:-1],hex(B)[2:-1],hex(S)[2:-1])
        response = "<r s='%s' B='%s' />" % (salt, hex(B)[2:-1])
        request.session["srp_M"] = hashlib.sha256(Mstr).hexdigest()
    return HttpResponse(response, mimetype="text/xml")

# Step 2: The client sends its proof of S. The server confirms, and sends its proof of S.    
def verify(request):
    import hashlib
    from django.contrib import auth
    if request.POST["M"] == request.session["srp_M"]:
        # H(A, M, K)
        user = auth.authenticate(username=request.session["srp_I"], password=str(request.session["srp_v"]))
        if user != None:
            response = "<M>%s</M>" % hashlib.sha256("%s%s%s" % (request.session["srp_A"], request.session["srp_M"], request.session["srp_S"])).hexdigest()
            auth.login(request, user)
        else:
            response = "<error>Authentication failed. This is likely a server problem.</error>"
    else:
        response = "<error>Invalid username or password.</error>"
    try:
        del request.session["srp_I"]
        del request.session["srp_v"]
        del request.session["srp_M"]
        del request.session["srp_S"]
        del request.session["srp_A"]
    except KeyError:
        pass
    return HttpResponse(response, mimetype="text/xml")
