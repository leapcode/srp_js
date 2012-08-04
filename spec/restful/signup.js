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

  it("fetches a salt from /register/salt", function(){
    var callback = sinon.spy();
    this.srp.register_receive_salt = callback;
    this.srp.register();
    this.expectRequest('register/salt/', "I=user")
    this.respondXML("<salt>5d3055e0acd3ddcfc15</salt>");
    expect(callback.called).toBeTruthy();
  });

  it("receives the salt from /register/salt", function(){
    var callback = sinon.spy();
    this.srp.remote.register_send_verifier = callback;
    this.srp.register();
    this.expectRequest('register/salt/', "I=user")
    this.respondXML("<salt>5d3055e0acd3ddcfc15</salt>");
    expect(callback).toHaveBeenCalledWith("adcd57b4a4a05c2e205b0b7b30014d9ff635d8d8db2f502f08e9b9c132800c44", this.srp.registered_user);
  });

  it("identifies after successful registration (INTEGRATION)", function(){
    var callback = sinon.spy();
    this.srp.identify = callback;
    this.srp.register();
    this.expectRequest('register/salt/', "I=user")
    this.respondXML("<salt>5d3055e0acd3ddcfc15</salt>");
    this.expectRequest('register/user/', "v=adcd57b4a4a05c2e205b0b7b30014d9ff635d8d8db2f502f08e9b9c132800c44");
    this.respondXML("<ok />");
    expect(callback).toHaveBeenCalled();
  });

  it("identifies after successful registration with JSON (INTEGRATION)", function(){
    var callback = sinon.spy();
    this.srp.identify = callback;
    this.srp.register();
    this.expectRequest('register/salt/', "I=user")
    this.respondJSON({salt: "5d3055e0acd3ddcfc15"});
    this.expectRequest('register/user/', "v=adcd57b4a4a05c2e205b0b7b30014d9ff635d8d8db2f502f08e9b9c132800c44");
    this.respondJSON({ok: true});
    expect(callback).toHaveBeenCalled();
  });


});


