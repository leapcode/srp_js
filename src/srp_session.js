SRP.prototype.Session = function() {
  
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
  var authenticated = false;
  var I = document.getElementById("srp_username").value;
  var pass = document.getElementById("srp_password").value;
  var V;
  var salt;

  // *** Accessor methods ***

  // allows setting the random number A for testing

  this.calculateAndSetA = function(_a)
  {
    a = new BigInteger(_a, 16);
    A = g.modPow(a, N);
    Astr = A.toString(16);
    return Astr;
  };

  this.getAstr = function() {
    return Astr;
  }

  // Returns the user's identity
  this.getI = function()
  {
    return I;
  };

  // some 16 byte random number
  this.getSalt = function() {
    salt = salt || new BigInteger(64, rng).toString(16);
    return salt
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
    return new BigInteger(SHA256(s + SHA256(I + ":" + pass)), 16);
  };

  this.getV = function(salt)
  {
    V = V || this.getg().modPow(this.calcX(salt), this.getN());
    return V;
  }

  // Calculate S, M, and M2
  // This is the client side of the SRP specification
  this.calculations = function(salt, ephemeral)
  {    
    //S -> C: s | B
    var B = new BigInteger(ephemeral, 16); 
    var Bstr = ephemeral;
    // u = H(A,B)
    var u = new BigInteger(SHA256(Astr + Bstr), 16); 
    // x = H(s, H(I:p))
    var x = new BigInteger(SHA256(salt + SHA256(I + ":" + pass)), 16);
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
    if(K) return K;
    if(authenticated) {
      K = SHA256(S.toString(16));
      return K;
    }
    else
      this.onError("User has not been authenticated.");
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
}
