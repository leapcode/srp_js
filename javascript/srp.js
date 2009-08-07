function SRP(username, password, ser, base_url)
{
    // Variables that will be used in the SRP protocol
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
    var u = null;
    var x = null;
    var S = null;
    var K = null;
    var M = null;
    var M2 = null;
    var url = base_url;
    var server = ser;
    var that = this;
    var authenticated = false;
    var hash_import = false;
    var I = username;
    var p = password;
    var xhr = null;

    this.getI = function()
    {
        return I;
    };
    this.getxhr = function()
    {
        return xhr;
    };
    this.geturl = function()
    {
        return url;
    };
    this.getg = function()
    {
        return g;
    };
    this.getN = function()
    {
        return N;
    };
    this.calcX = function(s)
    {
        return new BigInteger(SHA256(s + SHA256(I + ":" + p)), 16);
    };

    function paths(str)
    {
        // For now, str will be the django path
        // This function will translate for other backends.
        if(server == "django")
        {
            return str;
        }
    };
    this.paths = paths;
    // Perform ajax requests at the specified url, with the specified parameters
    // Calling back the specified function.
    this.ajaxRequest = function(full_url, params, callback)
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

    // Get the text content of an XML node
    this.innerxml = function(node)
    {
        return node.firstChild.nodeValue;
    };

    // Check whether or not a variable is defined
    function isdefined ( variable)
    {
        return (typeof(window[variable]) != "undefined");
    };    
    // Start the login process by identifying the user
    this.identify = function()
    {
        var handshake_url = url + paths("handshake/");
        var params = "I="+I+"&A="+Astr;
        that.ajaxRequest(handshake_url, params, receive_salts);
    };

    // Receive login salts from the server, start calculations
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

    // Calculate S, M, and M2
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

    // Send M to the server
    function send_hash(M)
    {
        var params = "M="+M;
        var auth_url = url+paths("authenticate/");
        that.ajaxRequest(auth_url, params, confirm_authentication);
    };
    // Receive M2 from the server and verify it
    function confirm_authentication()
    {
        if(xhr.readyState == 4 && xhr.status == 200) {
            if(xhr.responseXML.getElementsByTagName("M").length > 0)
		    {
		        if(that.innerxml(xhr.responseXML.getElementsByTagName("M")[0]) == M2)
		        {
		            that.success();
	                authenticated = true;
	            }
		        else
		            that.error_message("Server key does not match");
		    }
		    else if (xhr.responseXML.getElementsByTagName("error").length > 0)
		    {
		        that.error_message(that.innerxml(xhr.responseXML.getElementsByTagName("error")[0]));
		    }
        }
    };
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
        // First check that the functions aren't already loaded
        if(that.isdefined("SHA1") && that.isdefined("MD5")) return;
        // Get the directory that this javascript file was loaded from
        var arr=that.srpPath.split("/");
        var path = arr.slice(0, arr.length-1).join("/");
        // If this file is called srp.min.js, we will load the packed hash file
        if(arr[arr.length-1] == "srp.min.js")
            import_file(path+"/hash.min.js");
        // Otherwise, this file is presumably srp.js, and we will load individual hash files
        else
        {
            import_file(path+"/MD5.js");
            import_file(path+"/SHA1.js");
        }        
    }
    // If someone wants to use the session key for encrypting traffic, they can
    // access the key with this function.
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

    // This function is called when authentication is successful.
    // Developers can set this to other functions in specific implementations
    // and change the functionality.
    this.success = function()
    {
        alert("Authentication successful.");
    };
    // If an error occurs, raise it as an alert.
    // Developers can set this to an alternative function to handle erros differently.
    this.error_message = function(t)
    {
        alert(t);
    };
};
// This line is run while the document is loading
// It gets a list of all <script> tags and finds the last instance.
// The path to this script is the "src" attribute of that tag.
SRP.prototype.srpPath = document.getElementsByTagName('script')[document.getElementsByTagName('script').length-1].getAttribute("src");
