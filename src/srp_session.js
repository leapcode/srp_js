SRP.prototype.Session = function() {
  
  // Variables session will be used in the SRP protocol
  var Nstr = "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3";
  var N = new BigInteger(Nstr, 16);
  var g = new BigInteger("2");
  var k = new BigInteger("bf66c44a428916cad64aa7c679f3fd897ad4c375e9bbb4cbf2f5de241d618ef0", 16);

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
    return new BigInteger(SHA256(hex2a(s + SHA256(I + ":" + pass))), 16);
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

  function hex2a(hex) {
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
  }

}
