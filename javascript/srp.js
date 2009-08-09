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
    var url = base_url;
    var server = ser;
    var that = this;
    var authenticated = false;
    var I = username;
    var p = password;
    var xhr = null;

    // *** Accessor methods ***

    // Returns the user's identity
    this.getI = function()
    {
        return I;
    };

    // Returns the XMLHttpRequest object
    this.getxhr = function()
    {
        return xhr;
    };

    // Returns the base URL
    this.geturl = function()
    {
        return url;
    };
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

    // Translates the django path to PHP and ASP.NET paths
    this.paths = function(str)
    {
        // For now, str will be the django path
        // This function will translate for other backends.
        if(server == "django")
        {
            return str;
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

    // *** Actions ***

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

    // Start the login process by identifying the user
    this.identify = function()
    {
        var handshake_url = url + that.paths("handshake/");
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
                // If there is no algorithm specified, calculate M given s, B, and P
                if(!response.getAttribute("a"))
                {
		            calculations(response.getAttribute("s"), response.getAttribute("B"), p);
                    that.ajaxRequest(url+that.paths("authenticate/"), "M="+M, confirm_authentication);
                }
                // If there is an algorithm specified, start the login process
                else
                    upgrade(response.getAttribute("s"), response.getAttribute("B"), response.getAttribute("a"), response.getAttribute("d"));
		    }
		    else if(xhr.responseXML.getElementsByTagName("error").length > 0)
                that.error_message(xhr.responseXML.getElementsByTagName("error")[0]);
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
		        that.error_message(that.innerxml(xhr.responseXML.getElementsByTagName("error")[0]));
        }
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
            alert(hashfun(dsalt+p));
            calculations(s, ephemeral, hashfun(dsalt+p));
            that.ajaxRequest(url+that.paths("upgrade/authenticate/"), "M="+M, confirm_upgrade);
        };
        window.setTimeout(do_upgrade,10);
    };

    // Receive the server's M, confirming that the server has HASH(p)
    // Next, send P in plaintext (this is the **only** time it should ever be sent plain text)
    function confirm_upgrade()
    {
        if(xhr.readyState == 4 && xhr.status == 200) {
            if(xhr.responseXML.getElementsByTagName("M").length > 0)
		    {
		        if(that.innerxml(xhr.responseXML.getElementsByTagName("M")[0]) == M2)
		        {
                    var auth_url = url + that.paths("upgrade/verifier/");
                    that.ajaxRequest(auth_url, "p="+p, confirm_verifier);
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

    // After sending the password, check that the response is OK, then reidentify
    function confirm_verifier()
    {
        if(xhr.readyState == 4 && xhr.status == 200) {
            if(xhr.responseXML.getElementsByTagName("ok").length > 0)
                that.identify();
            else
                that.error_message("Verifier could not be confirmed");
        }
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
        // First check that the functions aren't already loaded
        if(isdefined("SHA1") && isdefined("MD5")) return;
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
