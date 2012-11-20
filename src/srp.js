var srp = (function(){

  function signup()
  {
    this.remote.signup();
  };

  function login()
  {
    this.remote.login();
  };

  return {
    signup: signup,
    login: login
  }
}());

