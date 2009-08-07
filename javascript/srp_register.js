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
    SRP.prototype.register_receive_salt = function()
    {
        var xhr = that.getxhr();
        if(xhr.readyState == 4 && xhr.status == 200) {
            if(xhr.responseXML.getElementsByTagName("salt").length > 0)
            {
                var s = that.innerxml(xhr.responseXML.getElementsByTagName("salt")[0]);
                var x = that.calcX(s);
                var v = that.getg().modPow(x, that.getN());
                that.register_send_verifier(v.toString(16));
            }
            else if(xhr.responseXML.getElementsByTagName("error").length > 0)
            {
                that.error_message(that.innerxml(xhr.responseXML.getElementsByTagName("error")[0]));
            }
        }
    };
        // Send the verifier to the server
    SRP.prototype.register_send_verifier = function(v)
    {
        var params = "v="+v;
        var auth_url = that.geturl() + that.paths("register/user/");
        that.ajaxRequest(auth_url, params, that.register_user);
    };

    // The user has been registered successfully, now login
    SRP.prototype.register_user = function()
    {
        var xhr = that.getxhr();
        if(xhr.readyState == 4 && xhr.status == 200) {
	        if(xhr.responseXML.getElementsByTagName("ok").length > 0)
	        {
	            that.identify();
            }
        }
    };  
};
SRP_REGISTER();
