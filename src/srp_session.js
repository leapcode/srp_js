srp.Session = function(login, password, constants) {
  

  var constants = constants || new srp.Constants();
  var a = constants.randomEphemeral();
  var A = constants.calcA(a);
  var S = null;
  var K = null;
  var M = null;
  var M2 = null;
  var authenticated = false;
  var I = login;
  var pass = password;

  // *** Accessor methods ***

  // allows setting the random number A for testing

  this.calculateAndSetA = function(_a) {
    a = _a;
    A = constants.calcA(_a);
    return A;
  };

  this.signup = function() {
    var salt = constants.randomSalt();
    var x = constants.calcX(this.getI(), this.getPass(), salt);
    return {
      login: this.getI(),
      password_salt: salt,
      password_verifier: constants.calcV(x)
    };
  };

  this.handshake = function() {
    return { 
      login: this.getI(), 
      A: this.getA()
    };
  };

  this.getA = function() {
    return A;
  }

  // Returns the user's identity
  this.getI = function() {
    I = login || document.getElementById("srp_username").value;
    return I;
  };

  // Returns the password currently typed in
  this.getPass = function() {
    pass = password || document.getElementById("srp_password").value;
    return pass;
  };

  // Calculate S, M, and M2
  // This is the client side of the SRP specification
  this.calculations = function(salt, ephemeral)
  {    
    //S -> C: s | B
    var B = ephemeral;
    var x = constants.calcX(this.getI(), this.getPass(), salt);
    S = constants.calcS(a, A, B, x);
    K = constants.calcK(S);
    
    // M = H(H(N) xor H(g), H(I), s, A, B, K)
    var xor = constants.nXorG();
    M = constants.hash(xor + SHA256(I) + salt + A + B + K);
    //M2 = H(A, M, K)
    M2 = constants.hash(A + M + K);
  };


  this.getS = function() {
    return S;
  }

  this.getM = function() {
    return M;
  }

  this.validate = function(serverM2) {
    authenticated = (serverM2 && serverM2 == M2)
    return authenticated;
  }

  // If someone wants to use the session key for encrypting traffic, they can
  // access the key with this function.
  this.key = function()
  {
    if(K) {
      return K;
    } else {
      this.onError("User has not been authenticated.");
    }
  };

  // Encrypt plaintext using slowAES
  this.encrypt = function(plaintext)
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
};

