function SRP_REGISTER()
{
  var that;

  // Initiate the registration process
  SRP.prototype.register = function()
  {
    that = this;
    var handshake_url = this.geturl() + this.paths("register/salt/");
    var params = "I="+this.getI();
    this.ajaxRequest(handshake_url, params, this.register_receive_salt);
  };

  // Receive the salt for registration
  SRP.prototype.register_receive_salt = function(response)
  {
    if(response.salt)
    {
      var s = response.salt;
      var x = that.calcX(s);
      var v = that.getg().modPow(x, that.getN());
      that.register_send_verifier(v.toString(16));
    }
    else if(response.error)
    {
      that.error_message(response.error);
    }
  };
  // Send the verifier to the server
  SRP.prototype.register_send_verifier = function(v)
  {
    var params = "v="+v;
    var auth_url = that.geturl() + that.paths("register/user/");
    that.ajaxRequest(auth_url, params, that.registered_user);
  };

  // The user has been registered successfully, now login
  SRP.prototype.registered_user = function(response)
  {
    if(response.ok)
    {
      that.identify();
    }
  };  
};
SRP_REGISTER();
