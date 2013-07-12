srp.Calculate = function() {

  // Variables used in the SRP protocol
  var Nstr = "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3";
  var N = new BigInteger(Nstr, 16);
  var g = new BigInteger("2");
  var k = new BigInteger("bf66c44a428916cad64aa7c679f3fd897ad4c375e9bbb4cbf2f5de241d618ef0", 16);
  var rng = new SecureRandom();

  this.A = function(_a) { 
    a = new BigInteger(_a, 16);
    return g.modPow(a, N).toString(16);
  };

  // Calculates the X value
  // x = H(s, H(I:p))
  this.X = function(login, password, salt) {
    var salted = salt + this.hash(login + ":" + password)
    return this.hashHex(salted);
  };

  this.V = this.A;

  // u = H(A,B)
  this.U = function(A, B) {
    return this.hashHex(A + B); 
  };

  //S = (B - kg^x) ^ (a + ux)
  this.S = function(_a, _A, _B, _x) {
    var a = new BigInteger(_a, 16);
    var x = new BigInteger(_x, 16);
    var u = new BigInteger(this.U(_A, _B), 16);
    var B = new BigInteger(_B, 16);
    
    var kgx = k.multiply(g.modPow(x, N));  
    var aux = a.add(u.multiply(x)); 
    
    return B.subtract(kgx).modPow(aux, N).toString(16); 
  }

  this.K = function(_S) {
    return this.hashHex(_S);
  }

  this.nXorG = function() {
    var hashN = this.hashHex(Nstr);
    var hashG = this.hashHex(g.toString(16));
    return hexXor(hashN, hashG);
  };

  this.hashHex = function(hexString) {
    return this.hash(hex2a(hexString));
  };

  this.hash = function(string) {
    return SHA256(string);
  };


  this.isInvalidEphemeral = function(a) {
    return (g.modPow(a, N) == 0);
  };

  this.randomEphemeral = function() {
    var a = new BigInteger(32, rng);
    while(this.isInvalidEphemeral(a))
    {
      a = new BigInteger(32, rng);
    }
    return a.toString(16);
  };
  
  // some 16 byte random number
  this.randomSalt = function() {
    return new BigInteger(64, rng).toString(16);
  }

  function hex2a(hex) {
    var str = '';
    if(hex.length % 2) {
      hex = "0" + hex;
    }
    for (var i = 0; i < hex.length; i += 2)
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
  }

  function removeLeading0(hex) {
    if (hex[0] == "0") {
      return hex.substr(1);
    } else {
      return hex;
    }
  }

  function hexXor(a, b) {
    var str = '';
    for (var i = 0; i < a.length; i += 2) {
      var xor = parseInt(a.substr(i, 2), 16) ^ parseInt(b.substr(i, 2), 16)
      xor = xor.toString(16);
      str += (xor.length == 1) ? ("0" + xor) : xor
    }
    return str;
  }
};
