describe("Signup", function() {

  beforeEach(function() {
    this.srp = new SRP();
    this.xhr = sinon.useFakeXMLHttpRequest();
    var requests = this.requests = [];
    this.xhr.onCreate = function (xhr) {
      requests.push(xhr);
    };
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
    expect(this.requests.length).toBe(1);

    specHelper.respondXML(this.requests[0], "<salt>5d3055e0acd3ddcfc15</salt>");
    expect(callback.called).toBeTruthy();
  });

  it("receives the salt from /register/salt", function(){
    var callback = sinon.spy();
    this.srp.register_send_verifier = callback;
    this.srp.register();
    expect(this.requests.length).toBe(1);

    specHelper.respondXML(this.requests[0], "<salt>5d3055e0acd3ddcfc15</salt>");
    expect(callback).toHaveBeenCalledWith("adcd57b4a4a05c2e205b0b7b30014d9ff635d8d8db2f502f08e9b9c132800c44");
  });

  it("identifies after successful registration (INTEGRATION)", function(){
    var callback = sinon.spy();
    this.srp.identify = callback;
    this.srp.register();
    expect(this.requests.length).toBe(1);
    expect(this.requests[0].url).toBe("register/salt/");
    expect(this.requests[0].requestBody).toBe("I=user");
    specHelper.respondXML(this.requests[0], "<salt>5d3055e0acd3ddcfc15</salt>");
    expect(this.requests.length).toBe(2);
    expect(this.requests[1].url).toBe("register/user/");
    expect(this.requests[1].requestBody).toBe("v=adcd57b4a4a05c2e205b0b7b30014d9ff635d8d8db2f502f08e9b9c132800c44");
    specHelper.respondXML(this.requests[1], "<ok/>");
    expect(callback).toHaveBeenCalled();
  });


});


