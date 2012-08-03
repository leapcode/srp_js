function SRP()
{
  // Variables session will be used in the SRP protocol
  var Nstr = "115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3";
  var N = new BigInteger(Nstr, 16);
  var g = new BigInteger("2");
  var k = new BigInteger("c46d46600d87fef149bd79b81119842f3c20241fda67d06ef412d8f6d9479c58", 16);
  var rng = new SecureRandom();
  var a = new BigInteger(32, rng);
  var A = g.modPow(a, N);
  while(A.mod(N) == 0)
  {
    a = new BigInteger(32, rng);
    A = g.modPow(a, N);
  }
  var Astr = A.toString(16);
  var S = null;
  var K = null;
  var M = null;
  var M2 = null;
  var session = this;
  var authenticated = false;
  var I = document.getElementById("srp_username").value;
  var p = document.getElementById("srp_password").value;
  var remote = plainXHR();

  // *** Accessor methods ***

  // allows setting the random number A for testing

  this.calculateAndSetA = function(_a)
  {
    a = new BigInteger(_a, 16);
    A = g.modPow(a, N);
    Astr = A.toString(16);
    return Astr;
  };

  // Returns the user's identity
  this.getI = function()
  {
    return I;
  };

  // some 16 byte random number
  this.salt = function() {
    return new BigInteger(64, rng).toString(16);
  }

  // Returns the BigInteger, g
  this.getg = function()
  {
    return g;
  };

  // Returns the BigInteger, N
  this.getN = function()
  {
    return N;
  };

  // Calculates the X value and return it as a BigInteger
  this.calcX = function(s)
  {
    return new BigInteger(SHA256(s + SHA256(I + ":" + p)), 16);
  };

  this.calcV = function(salt)
  {
    return this.getg().modPow(this.calcX(salt), this.getN());
  }

  // Check whether or not a variable is defined
  function isdefined ( variable)
  {
    return (typeof(window[variable]) != "undefined");
  };    
  
  // *** Actions ***

  // Start the login process by identifying the user
  this.identify = function()
  {
    this.remote.handshake(I, Astr, receive_salts);
  };

  // Receive login salts from the server, start calculations
  function receive_salts(response)
  {
    if(response.error) {
      session.error_message(response.error);
  }
  // B = 0 will make the algorithm always succeed - refuse such a server
  // answer
    else if(response.B == 0) {
      session.error_message("Server send random number 0 - this is not allowed");
    }
    // If there is no algorithm specified, calculate M given s, B, and P
    else if(!response.a)
    {
      calculations(response.s, response.B, p);
      remote.authenticate(M, confirm_authentication)
    }
    // If there is an algorithm specified, start the login process
    else {
      upgrade(response.s, response.B, response.a, response.d);
    } 
  };
  
  // Calculate S, M, and M2
  // This is the client side of the SRP specification
  function calculations(s, ephemeral, pass)
  {    
    //S -> C: s | B
    var B = new BigInteger(ephemeral, 16); 
    var Bstr = ephemeral;
    // u = H(A,B)
    var u = new BigInteger(SHA256(Astr + Bstr), 16); 
    // x = H(s, H(I:p))
    var x = new BigInteger(SHA256(s + SHA256(I + ":" + pass)), 16);
    //S = (B - kg^x) ^ (a + ux)
    var kgx = k.multiply(g.modPow(x, N));  
    var aux = a.add(u.multiply(x)); 
    S = B.subtract(kgx).modPow(aux, N); 
    // M = H(H(N) xor H(g), H(I), s, A, B, K)
    var Mstr = A.toString(16) + B.toString(16) + S.toString(16); 
    M = SHA256(Mstr);
    M2 = SHA256(A.toString(16) + M + S.toString(16)); 
    //M2 = H(A, M, K)
  };

  // Receive M2 from the server and verify it
  function confirm_authentication(response)
  {
    if(response.M)
    {
      if(response.M == M2)
      {
        authenticated = true;
        session.success();
      }
      else
        session.error_message("Server key does not match");
    }
    else if (response.error)
      session.error_message(response.error);
  };

  // *** Upgrades ***

  // Start the process to upgrade the user's account
  function upgrade(s,ephemeral,algo,dsalt)
  {
    // First we need to import the hash functions
    import_hashes();

    // Once the hash functions are imported, do the calculations using the hashpass as the password
    function do_upgrade()
    {
      // If sha1 and md5 are still undefined, sleep again
      if(!isdefined("SHA1") || !isdefined("MD5"))
      {
        window.setTimeout(do_upgrade, 10);
        return;
      }
      if(algo == "sha1")
        hashfun = SHA1;
      else if(algo == "md5")
        hashfun = MD5;
      //alert(hashfun(dsalt+p));
      calculations(s, ephemeral, hashfun(dsalt+p));
      remote.upgrade(M, session.confirm_upgrade)
    };
    window.setTimeout(do_upgrade,10);
  };

  // Encrypt plaintext using slowAES
  function encrypt(plaintext)
  {
    var key = cryptoHelpers.toNumbers(session.key());
    var byteMessage = cryptoHelpers.convertStringToByteArray(plaintext);
    var iv = new Array(16);
    rng.nextBytes(iv);
    var paddedByteMessage = slowAES.getPaddedBlock(byteMessage, 0, byteMessage.length, slowAES.modeOfOperation.CFB);
    var ciphertext = slowAES.encrypt(paddedByteMessage, slowAES.modeOfOperation.CFB, key, key.length, iv).cipher;
    var retstring = cryptoHelpers.base64.encode(iv.concat(ciphertext));
    while(retstring.indexOf("+",0) > -1)
      retstring = retstring.replace("+", "_");
    return retstring;
  };

  // Receive the server's M, confirming session the server has HASH(p)
  // Next, send P in plaintext (this is the **only** time it should ever be sent plain text)
  function confirm_upgrade(response)
  {
    if(response.M)
    {
      if(response.M == M2)
      {
        K = SHA256(S.toString(16));
        var auth_url = session.geturl() + session.paths("upgrade/verifier/");
        session.ajaxRequest(auth_url, "p="+encrypt(p)+"&l="+p.length, confirm_verifier);
      }
      else
        session.error_message("Server key does not match");
    }
    else if (response.error)
    {
      session.error_message(response.error);
    }
  };

  // After sending the password, check session the response is OK, then reidentify
  function confirm_verifier(response)
  {
    K = null;
    if(response.ok)
      session.identify();
    else
      session.error_message("Verifier could not be confirmed");
  };

  // This loads javascript libraries. Fname is the path to the library to be imported
  function import_file(fname)
  {
    var scriptElt = document.createElement('script');
    scriptElt.type = 'text/javascript';
    scriptElt.src = fname;
    document.getElementsByTagName('head')[0].appendChild(scriptElt);
  };
  // If we need SHA1 or MD5, we need to load the javascript files
  function import_hashes()
  {
    // First check session the functions aren't already loaded
    if(isdefined("SHA1") && isdefined("MD5")) return;
    // Get the directory session this javascript file was loaded from
    var arr=session.srpPath.split("/");
    var path = arr.slice(0, arr.length-1).join("/");
    // If this file is called srp.min.js, we will load the packed hash file
    if(arr[arr.length-1] == "srp.min.js")
      import_file(path+"/crypto.min.js");
    // Otherwise, this file is presumably srp.js, and we will load individual hash files
    else
    {
      import_file(path+"/MD5.js");
      import_file(path+"/SHA1.js");
      import_file(path+"/cryptoHelpers.js");
      import_file(path+"/aes.js");
    }        
  }

  // This function is called when authentication is successful.
  // Developers can set this to other functions in specific implementations
  // and change the functionality.
  this.success = function()
  {
    var forward_url = document.getElementById("srp_forward").value;
    if(forward_url.charAt(0) != "#")
      window.location = forward_url;
    else
    {
      window.location = forward_url;
      alert("Login successful.");
    }
  };
  // If someone wants to use the session key for encrypting traffic, they can
  // access the key with this function.
  this.key = function()
  {
    if(K == null)
      if(authenticated)
    {
      K = SHA256(S.toString(16));
      return K;
    }
    else
      session.error_message("User has not been authenticated.");
    else
      return K;
  };

  // If an error occurs, raise it as an alert.
  // Developers can set this to an alternative function to handle erros differently.
  this.error_message = function(t)
  {
    alert(t);
  };


  // exposing the remote handler so it can be modified
  this.remote = remote;

};
  // This line is run while the document is loading
  // It gets a list of all <script> tags and finds the last instance.
  // The path to this script is the "src" attribute of that tag.
  SRP.prototype.srpPath = document.getElementsByTagName('script')[document.getElementsByTagName('script').length-1].getAttribute("src");
