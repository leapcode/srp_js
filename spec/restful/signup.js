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

  it("calculates the right x", function(){
    expect(this.srp.session.calcX("7686acb8").toString(16)).toBe('84d6bb567ddf584b1d8c8728289644d45dbfbb02deedd05c0f64db96740f0398');
  });

  it("identifies after successful registration (INTEGRATION)", function(){
    var callback = sinon.spy();
    this.srp.identify = callback;
    this.srp.session.getSalt = function() {return "4c78c3f8"};
    this.srp.register();
    this.expectRequest('users', "user[login]=testuser&user[password_salt]=4c78c3f8&user[password_verifier]=474c26aa42d11f20544a00f7bf9711c4b5cf7aab95ed448df82b95521b96668e7480b16efce81c861870302560ddf6604c67df54f1d04b99d5bb9d0f02c6051ada5dc9d594f0d4314e12f876cfca3dcd99fc9c98c2e6a5e04298b11061fb8549a22cde0564e91514080df79bca1c38c682214d65d590f66b3719f954b078b83c", 'POST')
    this.respondJSON({password_salt: "4c78c3f8", login: "testuser", ok: "true"});
    expect(callback).toHaveBeenCalled();
  });

});


