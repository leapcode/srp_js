describe("Signup", function() {

  beforeEach(function() {
    this.srp = new SRP(jqueryRest());
    specHelper.setupFakeXHR.apply(this);
  });

  afterEach(function() {
    this.xhr.restore();
  });

  it("has a register function", function() {
    expect(typeof this.srp.register).toBe('function');
  });

  it("identifies after successful registration (INTEGRATION)", function(){
    var callback = sinon.spy();
    this.srp.identify = callback;
    this.srp.session.getSalt = function() {return "5d3055e0acd3ddcfc15"};
    this.srp.register();
    this.expectRequest('users', "user[login]=user&user[password_salt]=5d3055e0acd3ddcfc15&user[password_verifier]=adcd57b4a4a05c2e205b0b7b30014d9ff635d8d8db2f502f08e9b9c132800c44")
    this.respondJSON({password_salt: "5d3055e0acd3ddcfc15", login: "user", ok: "true"});
    expect(callback).toHaveBeenCalled();
  });

});


