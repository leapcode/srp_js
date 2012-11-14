jqueryRest = function() {

  // we do not fetch the salt from the server
  function register(session, callback)
  {
    sendVerifier(session, callback);
  }

  function sendVerifier(session, callback) {
    var salt = session.getSalt();
    $.post("users.json", { user:
      { login: session.getI(),
        password_salt: salt,
        password_verifier: session.getV(salt).toString(16)}
    }, callback);
  }

  function handshake(session, callback) {
    $.post("sessions.json", { login: session.getI(),
      A: session.getAstr()}, callback);
  }

  function authenticate(session, success) {
    $.ajax({
      url: "sessions/" + session.getI() + ".json",
      type: 'PUT',
      data: {client_auth: session.getM()},
      success: success
    });
  }

  return {
    register: register,
    register_send_verifier: sendVerifier,
    handshake: handshake,
    authenticate: authenticate
  };
};
