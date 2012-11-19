jqueryRest = function() {

  // we do not fetch the salt from the server
  function register(session)
  {
    return sendVerifier(session);
  }

  function sendVerifier(session) {
    var salt = session.getSalt();
    return $.post("users.json", { user:
      { login: session.getI(),
        password_salt: salt,
        password_verifier: session.getV(salt).toString(16)
      }
    });
  }

  function handshake(session) {
    return $.post("sessions.json", { login: session.getI(), A: session.getAstr()});
  }

  function authenticate(session) {
    return $.ajax({
      url: "sessions/" + session.getI() + ".json",
      type: 'PUT',
      data: {client_auth: session.getM()},
    });
  }

  return {
    register: register,
    register_send_verifier: sendVerifier,
    handshake: handshake,
    authenticate: authenticate
  };
};
