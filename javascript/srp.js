var srp_N = null;
var srp_Nstr = "115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3";
var srp_g = null;
var srp_k = null;
var srp_a = null;
var srp_A = null;
var srp_Astr = null;
var srp_b = null;
var srp_B = null;
var srp_Bstr = null;
var srp_I = null;
var srp_u = null;
var srp_p = null;
var srp_x = null;
var srp_S = null;
var srp_K = null;
var srp_M = null;
var srp_M2 = null;
var xhr;
var srp_url = window.location.protocol+"//"+window.location.host+"/srp/";
function srp_register()
{
    srp_N = str2bigInt(srp_Nstr, 16, 0);
    srp_g = str2bigInt("2", 10, 0);
    srp_k = str2bigInt("c46d46600d87fef149bd79b81119842f3c20241fda67d06ef412d8f6d9479c58", 16, 0);
    srp_I = document.getElementById("srp_username").value;
    srp_register_salt(srp_I);
    return false;
};
function srp_register_salt(I)
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
        srp_error_message("Ajax not supported.");
        return;
    }
    if(xhr){
        var srp_handshake_url = srp_url + "register/salt/";
        var srp_params = "I="+I;        
        xhr.onreadystatechange = srp_register_receive_salt;
        xhr.open("POST", srp_handshake_url, true);
        xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        xhr.setRequestHeader("Content-length", srp_params.length);
        xhr.setRequestHeader("Connection", "close");
        
        xhr.send(srp_params);
    }
    else
    {
        srp_error_message("Ajax failed.");
    }
};
function srp_register_receive_salt()
{
    if(xhr.readyState == 4 && xhr.status == 200) {
		if(xhr.responseXML.getElementsByTagName("salt").length > 0)
		{
		    s = innerxml(xhr.responseXML.getElementsByTagName("salt")[0]);
		    srp_x = srp_calculate_x(s);
		    v = powMod(srp_g, srp_x, srp_N);
		    srp_register_send_verifier(bigInt2str(v, 16));
		}
		else if(xhr.responseXML.getElementsByTagName("error").length > 0)
		{
		    srp_error_message(innerxml(xhr.responseXML.getElementsByTagName("error")[0]));
		}
	}
};
function srp_register_send_verifier(v)
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
        srp_error_message("Ajax not supported.");
        return;
    }
    if(xhr){
        var srp_params = "v="+v;
        var srp_auth_url = srp_url+ "register/user/";

        xhr.onreadystatechange = srp_register_user;
        xhr.open("POST", srp_auth_url, true);
        xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        xhr.setRequestHeader("Content-length", srp_params.length);
        xhr.setRequestHeader("Connection", "close");
        
        xhr.send(srp_params);
    }
    else
    {
        srp_error_message("Ajax failed.");
    }
};
function srp_register_user()
{
    if(xhr.readyState == 4 && xhr.status == 200) {
		if(xhr.responseXML.getElementsByTagName("ok").length > 0)
		{
		    srp_identify();
        }
    }
};
function srp_identify()
{
    srp_N = str2bigInt(srp_Nstr, 16, 0);
    srp_g = str2bigInt("2", 10, 0);
    srp_k = str2bigInt("c46d46600d87fef149bd79b81119842f3c20241fda67d06ef412d8f6d9479c58", 16, 0);
    srp_a = randBigInt(32, 1);
    // A = g**a % N
    srp_A = powMod(srp_g,srp_a,srp_N);
    srp_I = document.getElementById("srp_username").value;

    srp_Astr = bigInt2str(srp_A, 16)
    // C -> S: A | I
    srp_send_identity(srp_Astr, srp_I);
    return false;
};
function srp_send_identity(Astr, I)
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
        srp_error_message("Ajax not supported.");
        return;
    }
    if(xhr){
        var srp_handshake_url = srp_url + "handshake/";
        var srp_params = "I="+I+"&A="+Astr;        
        xhr.onreadystatechange = srp_receive_salts;
        xhr.open("POST", srp_handshake_url, true);
        xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        xhr.setRequestHeader("Content-length", srp_params.length);
        xhr.setRequestHeader("Connection", "close");
        
        xhr.send(srp_params);
    }
    else
    {
        srp_error_message("Ajax failed.");
    }
};
function srp_receive_salts()
{
    if(xhr.readyState == 4 && xhr.status == 200) {
		if(xhr.responseXML.getElementsByTagName("r").length > 0)
		{
		    response = xhr.responseXML.getElementsByTagName("r")[0];
		    srp_calculations(response.getAttribute("s"), response.getAttribute("B"));
		}
		else if(xhr.responseXML.getElementsByTagName("error").length > 0)
		{
		    // This probably means A % N == 0, which means we need to generate
	        // a new A and reidentify.
            srp_identify();
		}
	}
};

function srp_calculate_x(s)
{
    var p = document.getElementById("srp_password").value;
    return str2bigInt(SHA256(s + SHA256(srp_I + ":" + p)), 16, 0);
};

function srp_calculations(s, B)
{
    
    //S -> C: s | B
    srp_B = str2bigInt(B, 16, 0);
    srp_Bstr = B;
    // u = H(A,B)
    srp_u = str2bigInt(SHA256(srp_Astr + srp_Bstr), 16, 0);    
    // x = H(s, H(I:p))
    srp_x = srp_calculate_x(s);
    //S = (B - kg^x) ^ (a + ux)
    var kgx = mult(srp_k, powMod(srp_g, srp_x, srp_N));
    var aux = add(srp_a, mult(srp_u, srp_x));
    srp_S = powMod(sub(srp_B, kgx), aux, srp_N);
    // M = H(H(N) xor H(g), H(I), s, A, B, K)
    var Mstr = bigInt2str(srp_A, 16) + bigInt2str(srp_B,16) + bigInt2str(srp_S,16);
    srp_M = SHA256(Mstr);
    srp_send_hash(srp_M);
    //M2 = H(A, M, K)
    srp_M2 = SHA256(bigInt2str(srp_A, 16)+srp_M+bigInt2str(srp_S, 16));
};


function srp_send_hash(M)
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
        srp_error_message("Ajax not supported.");
        return;
    }
    if(xhr){
        var srp_params = "M="+M;
        var srp_auth_url = srp_url+ "authenticate/";

        xhr.onreadystatechange = srp_confirm_authentication;
        xhr.open("POST", srp_auth_url, true);
        xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        xhr.setRequestHeader("Content-length", srp_params.length);
        xhr.setRequestHeader("Connection", "close");
        
        xhr.send(srp_params);
    }
    else
    {
        srp_error_message("Ajax failed.");
    }
};

function srp_confirm_authentication()
{
    if(xhr.readyState == 4 && xhr.status == 200) {
        if(xhr.responseXML.getElementsByTagName("M").length > 0)
		{
		    if(innerxml(xhr.responseXML.getElementsByTagName("M")[0]) == srp_M2)
		        srp_success();
		    else
		        srp_error_message("Server key does not match");
		}
		else if (xhr.responseXML.getElementsByTagName("error").length > 0)
		{
		    srp_error_message(innerxml(xhr.responseXML.getElementsByTagName("error")[0]));
		}
    }
};
function innerxml (node)
{
    return node.firstChild.nodeValue;
};
function srp_error_message(t)
{
    alert(t);
};
