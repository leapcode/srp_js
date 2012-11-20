var srp = (function(){

  function signup()
  {
    srp.remote.signup();
  };

  function login()
  {
    srp.remote.login();
  };

  return {
    signup: signup,
    login: login
  }
}());

