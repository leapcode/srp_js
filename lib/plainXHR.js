plainXHR = function() {

  function getUrl()
  {
    return "";
  }

  function paths(path)
  {
    return path
  }

  // Perform ajax requests at the specified path, with the specified parameters
  // Calling back the specified function.
  function ajaxRequest(relative_path, params, callback)
  {
    var full_url = this.geturl() + this.paths(relative_path);
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
      xhr.open("POST", full_url, true);
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

  function register(session, callback)
  {
    this.ajaxRequest("register/salt/", "I="+session.getI(), callback);
  }

  function sendVerifier(session, callback) {
    this.ajaxRequest("register/user/", "v="+session.getV().toString(16), callback);
  }

  function handshake(I, Astr, callback) {
    this.ajaxRequest("handshake/", "I="+I+"&A="+Astr, callback);
  }

  function authenticate(M, callback) {
    this.ajaxRequest("authenticate/", "M="+M, callback);
  }

  function upgrade(M, callback) {
    this.ajaxRequest("upgrade/authenticate/", "M="+M, callback);
  }

  return {
    geturl: getUrl,
    paths: paths,
    ajaxRequest: ajaxRequest,
    register: register,
    register_send_verifier: sendVerifier,
    handshake: handshake,
    authenticate: authenticate,
    upgrade: upgrade
  }
}
