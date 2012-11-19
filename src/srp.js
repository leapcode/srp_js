function SRP(remote, session)
{
  var srp = this;
  session = session || new this.Session();
  session.onError = session.onError || this.error;
  this.remote = remote;
  this.session = session;

  // Start the login process by identifying the user
  this.identify = function(success, error)
  {
    store_callbacks(success, error);
    remote.handshake(session)
    .success(receive_salts)
    .error(srp.error);

    // Receive login salts from the server, start calculations
    function receive_salts(response)
    {
      // B = 0 will make the algorithm always succeed
      // -> refuse such a server answer
      if(response.B === 0) {
        srp.error("Server send random number 0 - could not login.");
      }
      else if(! response.salt || response.salt === 0) {
        srp.error("Server failed to send salt - could not login.");
      } 
      else 
      {
        session.calculations(response.salt, response.B);
        remote.authenticate(session)
        .success(confirm_authentication)
        .error(srp.error);
      }
    }

    // Receive M2 from the server and verify it
    // If an error occurs, raise it as an alert.
    function confirm_authentication(response)
    {
      if (session.validate(response.M2))
        srp.success();
      else
        srp.error("Server key does not match");
    };
  };

  // Initiate the registration process
  this.register = function(success, error)
  {
    store_callbacks(success, error);
    remote.register(session)
    .success(srp.registered_user)
    .error(srp.error);
  };

  // The user has been registered successfully, now login
  this.registered_user = function(response)
  {
    // TODO: This can go if response has an error code
    if(response.errors) {
      srp.error(response.errors)
    }
    else {
      srp.identify();
    }
  };  

  // This function is called when authentication is successful.
  // It's a dummy. Please hand the real thing to the call to identify.
  this.success = function()
  {
    alert("Login successful.");
  };

  // Minimal error handling - set remote.onError to sth better to overwrite.
  this.error = function(text)
  {
    alert(text);
  };

  function store_callbacks(success, error) {
    if (typeof success == "function") {
      srp.success = success;
    }
    if (typeof error == "function") {
      srp.error = error;
    }
  }
};

