var srp = (function(){

  function signup()
  {
    srp.remote.signup();
  };

  function login()
  {
    srp.remote.login();
  };

  function addToForm()
  {
    srp.remote.addToForm();
  };

  return {
    signup: signup,
    login: login,
    addToForm: addToForm
  }
}());

