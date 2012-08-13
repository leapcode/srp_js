function SRP(remote, session)
{
  var srp = this;
  session = session || new this.Session();
  remote = remote || new this.Remote();

  // Start the login process by identifying the user
  this.identify = function()
  {
    remote.handshake(session, receive_salts);
  };

  // Receive login salts from the server, start calculations
  function receive_salts(response)
  {
    // B = 0 will make the algorithm always succeed
    // -> refuse such a server answer
    if(response.B == 0) {
      srp.error("Server send random number 0 - this is not allowed");
    } else {
      session.calculations(response.s, response.B);
      remote.authenticate(session, confirm_authentication)
    }
  };

  // Receive M2 from the server and verify it
  // If an error occurs, raise it as an alert.
  function confirm_authentication(response)
  {
    if (session.validate(response.M))
      srp.success();
    else
      alertErrorMessage("Server key does not match");
  };

  // Minimal error handling - set remote.onError to sth better to overwrite.
  this.error = function(text)
  {
    alert(text);
  };
  remote.onError = remote.onError || this.error;
  session.onError = session.onError || this.error;

  // This function is called when authentication is successful.
  // Developers can set this to other functions in specific implementations
  // and change the functionality.
  this.success = function()
  {
    var forward_url = document.getElementById("srp_forward").value;
    if(forward_url.charAt(0) != "#")
      window.location = forward_url;
    else
    {
      window.location = forward_url;
      alert("Login successful.");
    }
  };

};
