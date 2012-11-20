describe("Loading SRP", function() {
  it("provides a signup function", function() {
    expect(typeof srp.signup).toBe('function');
  });

  it("provides session which calculates the right x", function(){
    srp.session = new srp.Session();
    expect(srp.session.calcX("7686acb8").toString(16)).toBe('84d6bb567ddf584b1d8c8728289644d45dbfbb02deedd05c0f64db96740f0398');
  });
});

describe("Signup with srp var", function() {
  
  beforeEach(function() {
    specHelper.setupFakeXHR.apply(this);
    srp.session = new srp.Session();
  });

  afterEach(function() {
    this.xhr.restore();
  });
  
  it("identifies after successful registration (INTEGRATION)", function(){
    var callback = sinon.spy();
    srp.signedUp = callback;
    srp.session.getSalt = function() {return "4c78c3f8"};
    srp.signup();
    this.expectRequest('/users.json', "user[login]=testuser&user[password_salt]=4c78c3f8&user[password_verifier]=474c26aa42d11f20544a00f7bf9711c4b5cf7aab95ed448df82b95521b96668e7480b16efce81c861870302560ddf6604c67df54f1d04b99d5bb9d0f02c6051ada5dc9d594f0d4314e12f876cfca3dcd99fc9c98c2e6a5e04298b11061fb8549a22cde0564e91514080df79bca1c38c682214d65d590f66b3719f954b078b83c", 'POST')
    this.respondJSON({password_salt: "4c78c3f8", login: "testuser", ok: "true"});
    expect(callback).toHaveBeenCalled();
  });

});

