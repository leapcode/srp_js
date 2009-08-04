function SRP(username, password, ser, base_url)
{
    var Nstr = "115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3";
    var N = new BigInteger(Nstr, 16);
    var g = new BigInteger("2");
    var k = new BigInteger("c46d46600d87fef149bd79b81119842f3c20241fda67d06ef412d8f6d9479c58", 16);
    var rng = new SecureRandom();
    var a = new BigInteger(32, rng);
    var A = g.modPow(a, N);
    var Astr = A.toString(16);
    var B = null;
    var Bstr = null;
    var I = username;
    var u = null;
    var p = password;
    var x = null;
    var S = null;
    var K = null;
    var M = null;
    var M2 = null;
    var xhr = null;
    var url = base_url;
    var server = ser;
    var that = this;
    var authenticated = false;
    var hash_import = false;
    
    function paths(str)
    {
        // For now, str will be the django path
        // This function will translate for other backends.
        if(server == "django")
        {
            return str;
        }
    };
    function ajaxRequest(full_url, params, callback)
    {
        if( window.XMLHttpRequest)
            xhr = new XMLHttpRequest();
        else if (window.ActiveXObject){
            try{
                xhr = new ActiveXObject("Microsoft.XMLHTTP");
            }catch (e){}
        }
        else
        {
            that.error_message("Ajax not supported.");
            return;
        }
        if(xhr){
            xhr.onreadystatechange = callback;
            xhr.open("POST", full_url, true);
            xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
            xhr.setRequestHeader("Content-length", params.length);
            xhr.setRequestHeader("Connection", "close");
            xhr.send(params);
        }
        else
        {
            that.error_message("Ajax failed.");
        }        
    };
    
    this.register = function()
    {
        var handshake_url = url + paths("register/salt/");
        var params = "I="+I;
        ajaxRequest(handshake_url, params, register_receive_salt);
    };
    function register_receive_salt()
    {
        if(xhr.readyState == 4 && xhr.status == 200) {
	        if(xhr.responseXML.getElementsByTagName("salt").length > 0)
	        {
	            var s = innerxml(xhr.responseXML.getElementsByTagName("salt")[0]);
	            x = new BigInteger(SHA256(s + SHA256(I + ":" + p)), 16);
	            var v = g.modPow(x, N);
	            register_send_verifier(v.toString(16));
	        }
	        else if(xhr.responseXML.getElementsByTagName("error").length > 0)
	        {
	            that.error_message(innerxml(xhr.responseXML.getElementsByTagName("error")[0]));
	        }
        }
    };
    function register_send_verifier(v)
    {
        var params = "v="+v;
        var auth_url = url + paths("register/user/");
        ajaxRequest(auth_url, params, register_user);
    };
    function register_user()
    {
        if(xhr.readyState == 4 && xhr.status == 200) {
		    if(xhr.responseXML.getElementsByTagName("ok").length > 0)
		    {
		        that.identify();
            }
        }
    };
    
    function innerxml (node)
    {
        return node.firstChild.nodeValue;
    };
    this.identify = function()
    {
        var handshake_url = url + paths("handshake/");
        var params = "I="+I+"&A="+Astr;
        ajaxRequest(handshake_url, params, receive_salts);
    };
    function receive_salts()
    {
        if(xhr.readyState == 4 && xhr.status == 200) {
		    if(xhr.responseXML.getElementsByTagName("r").length > 0)
		    {
		        var response = xhr.responseXML.getElementsByTagName("r")[0];
		        calculations(response.getAttribute("s"), response.getAttribute("B"));
		    }
		    else if(xhr.responseXML.getElementsByTagName("error").length > 0)
		    {
		        // This probably means A % N == 0, which means we need to generate
	            // a new A and reidentify.
                that.identify();
		    }
	    }
    };
    function calculations(s, ephemeral)
    {    
        //S -> C: s | B
        B = new BigInteger(ephemeral, 16); 
        Bstr = ephemeral;
        // u = H(A,B)
        u = new BigInteger(SHA256(Astr + Bstr), 16); 
        // x = H(s, H(I:p))
        x = new BigInteger(SHA256(s + SHA256(I + ":" + p)), 16);
        //S = (B - kg^x) ^ (a + ux)
        var kgx = k.multiply(g.modPow(x, N));  
        var aux = a.add(u.multiply(x)); 
        S = B.subtract(kgx).modPow(aux, N); 
        // M = H(H(N) xor H(g), H(I), s, A, B, K)
        var Mstr = A.toString(16) + B.toString(16) + S.toString(16); 
        M = SHA256(Mstr);
        M2 = SHA256(A.toString(16) + M + S.toString(16)); 
        send_hash(M);
        //M2 = H(A, M, K)
    };
    function send_hash(M)
    {
        var params = "M="+M;
        var auth_url = url+paths("authenticate/");
        ajaxRequest(auth_url, params, confirm_authentication);
    };
    function confirm_authentication()
    {
        if(xhr.readyState == 4 && xhr.status == 200) {
            if(xhr.responseXML.getElementsByTagName("M").length > 0)
		    {
		        if(innerxml(xhr.responseXML.getElementsByTagName("M")[0]) == M2)
		        {
                    import_hashes();
		            that.success();
	                authenticated = true;
	            }
		        else
		            that.error_message("Server key does not match");
		    }
		    else if (xhr.responseXML.getElementsByTagName("error").length > 0)
		    {
		        that.error_message(innerxml(xhr.responseXML.getElementsByTagName("error")[0]));
		    }
        }
    };
    function import_hashes()
    {
        if(that.isdefined("SHA1") && that.isdefined("MD5")) return;
        var arr=srpPath.split("/");
        var path = arr.slice(0, arr.length-1).join("/");
        if(arr[arr.length-1] == "srp.min.js")
        {
            var scriptElt = document.createElement('script');
            scriptElt.type = 'text/javascript';
            scriptElt.src = path+"/hash.min.js";
            document.getElementsByTagName('head')[0].appendChild(scriptElt);
        }
        else
        {
            var scriptElt = document.createElement('script');
            scriptElt.type = 'text/javascript';
            scriptElt.src = path +"/MD5.js";
            document.getElementsByTagName('head')[0].appendChild(scriptElt);
            scriptElt = document.createElement('script');
            scriptElt.type = 'text/javascript';
            scriptElt.src = path +"/SHA1.js";
            document.getElementsByTagName('head')[0].appendChild(scriptElt);
        }
        
    }
    this.key = function()
    {
        if(K == null)
            if(authenticated)
            {
                K = SHA256(S);
                return K;
            }
            else
                that.error_message("User has not been authenticated.");
        else
            return K;
    };
    this.success = function()
    {
        alert("Authentication successful.");
    };
    this.error_message = function(t)
    {
        alert(t);
    };
    this.isdefined = function ( variable)
    {
        return (typeof(window[variable]) == "undefined")?  false: true;
    };
};
var srpPath = document.getElementsByTagName('script')[document.getElementsByTagName('script').length-1].getAttribute("src");
