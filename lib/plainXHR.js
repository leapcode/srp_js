//
// SRP JS - Plain XHR module
//
// This is deprecated - unless you are using srp-js with the original drupal
// server side I recommend you use a different API such as restful.js
//
// This code has been largely refactored, tests are still passing but I did
// not test it with the server itself.

SRP.prototype.Remote = function() {

  // Perform ajax requests at the specified path, with the specified parameters
  // Calling back the specified function.
  function ajaxRequest(url, params, callback)
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
      session.error_message("Ajax not supported.");
      return;
    }
    if(xhr){
      xhr.onreadystatechange = function() {
        if(xhr.readyState == 4 && xhr.status == 200) {
          callback(parseResponse());
        }
      };
      xhr.open("POST", url, true);
      xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
      xhr.setRequestHeader("Content-length", params.length);
      xhr.send(params);
    }
    else
    {
      session.error_message("Ajax failed.");
    }        
  };

  function parseResponse() {
    if (responseIsXML()) {
      return parseXML(xhr.responseXML);
    } else if (responseIsJSON()) {
      return JSON.parse(xhr.responseText);
    } 
  };

  function responseIsXML() {
    return (xhr.responseType == 'document') || 
           (xhr.getResponseHeader("Content-Type").indexOf('application/xml') >= 0)
  }

  function responseIsJSON() {
    return (xhr.responseType == 'json') || 
           (xhr.getResponseHeader("Content-Type").indexOf('application/json') >= 0)
  }

  function parseXML(xml) {
    if (xml.getElementsByTagName("r").length > 0) {
      return parseAttributesOfElement(xml.getElementsByTagName("r")[0]);
    } else {
      return parseNodes(xml.childNodes);
    }
  };

  function parseAttributesOfElement(elem) {
    var response = {};
    for (var i = 0; i < elem.attributes.length; i++) {
      var attrib = elem.attributes[i];
      if (attrib.specified) {
        response[attrib.name] = attrib.value;
      }
    }
    return response;
  };

  function parseNodes(nodes) {
    var response = {};
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      response[node.tagName] = node.textContent || true;
    }
    return response;
  };
  
  // Drupal version fetches the salt from the server. No idea why but this
  // should still do it.
  this.register = function(session, callback)
  {
    var that = this;
    ajaxRequest("register/salt/", "I="+session.getI(), receive_salt);

    function receive_salt(response)
    {
      if(response.salt)
      {
        var s = response.salt;
        var v = session.getV(s);
        that.sendVerifier(session, callback);
      }
    };
  }

  this.sendVerifier = function(session, callback) {
    ajaxRequest("register/user/", "v="+session.getV().toString(16), callback);
  }

  this.handshake = function(session, callback) {
    ajaxRequest("handshake/", "I="+session.getI()+"&A="+session.getAstr(), callback);
  }

  this.authenticate = function(session, callback) {
    ajaxRequest("authenticate/", "M="+session.getM(), callback);
  }
}
