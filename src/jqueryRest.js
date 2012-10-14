jqueryRest = function() {

  // Perform ajax requests at the specified path, with the specified parameters
  // Calling back the specified function.
  function ajaxRequest(relative_path, params, callback)
  {
    $.post(relative_path, params, callback)
  }

  function parseResponse() {
    if (responseIsXML()) {
      return parseXML(xhr.responseXML);
    } else if (responseIsJSON()) {
      return JSON.parse(xhr.responseText);
    } 
  }

  function responseIsXML() {
    return (xhr.responseType == 'document') || 
           (xhr.getResponseHeader("Content-Type").indexOf('application/xml') >= 0);
  }

  function responseIsJSON() {
    return (xhr.responseType == 'json') || 
           (xhr.getResponseHeader("Content-Type").indexOf('application/json') >= 0);
  }

  function parseXML(xml) {
    if (xml.getElementsByTagName("r").length > 0) {
      return parseAttributesOfElement(xml.getElementsByTagName("r")[0]);
    } else {
      return parseNodes(xml.childNodes);
    }
  }

  function parseAttributesOfElement(elem) {
    var response = {};
    for (var i = 0; i < elem.attributes.length; i++) {
      var attrib = elem.attributes[i];
      if (attrib.specified) {
        response[attrib.name] = attrib.value;
      }
    }
    return response;
  }

  function parseNodes(nodes) {
    var response = {};
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      response[node.tagName] = node.textContent || true;
    }
    return response;
  }

  // we do not fetch the salt from the server
  function register(session, callback)
  {
    sendVerifier(session, callback);
  }

  function sendVerifier(session, callback) {
    var salt = session.getSalt();
    ajaxRequest("users", { user:
      { login: session.getI(),
        password_salt: salt,
        password_verifier: session.getV(salt).toString(16)}
    }, callback);
  }

  function handshake(session, callback) {
    ajaxRequest("sessions", { login: session.getI(),
      A: session.getAstr()}, callback);
  }

  function authenticate(session, callback) {
    ajaxRequest("sessions/" + session.getI(), {client_auth: session.getM()}, callback);
  }

  return {
    ajaxRequest: ajaxRequest,
    register: register,
    register_send_verifier: sendVerifier,
    handshake: handshake,
    authenticate: authenticate
  };
};
