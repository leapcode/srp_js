srp.Account = function(login, password) {
  
  // Returns the user's identity
  this.login = function() {
    return login || document.getElementById("srp_username").value;
  };

  // Returns the password currently typed in
  this.password = function() {
    return password || document.getElementById("srp_password").value;
  };

}
