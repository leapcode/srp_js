

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

  it("instantiates SRP with a register function", function() {
    expect(typeof this.srp.register).toBe('function');
  });

  it("fetches a salt from /register/salt", function(){
    var callback = sinon.spy();
    this.srp.register_receive_salt = callback;
    this.srp.register();
    expect(this.requests.length).toBe(1);

    respondXML(this.requests[0], "<salt>5d3055e0acd3ddcfc15</salt>");
    expect(callback.called).toBeTruthy();
  });

  it("receives the salt from /register/salt", function(){
    var callback = sinon.spy();
    this.srp.register_send_verifier = callback;
    this.srp.register();
    expect(this.requests.length).toBe(1);

    respondXML(this.requests[0], "<salt>5d3055e0acd3ddcfc15</salt>");
    expect(callback).toHaveBeenCalledWith("adcd57b4a4a05c2e205b0b7b30014d9ff635d8d8db2f502f08e9b9c132800c44");
  });

  it("identifies after successful registration (INTEGRATION)", function(){
    var callback = sinon.spy();
    this.srp.identify = callback;
    this.srp.register();
    expect(this.requests.length).toBe(1);
    expect(this.requests[0].url).toBe("register/salt/");
    expect(this.requests[0].requestBody).toBe("I=user");
    respondXML(this.requests[0], "<salt>5d3055e0acd3ddcfc15</salt>");
    expect(this.requests.length).toBe(2);
    expect(this.requests[1].url).toBe("register/user/");
    expect(this.requests[1].requestBody).toBe("v=adcd57b4a4a05c2e205b0b7b30014d9ff635d8d8db2f502f08e9b9c132800c44");
    respondXML(this.requests[1], "<ok/>");
    expect(callback).toHaveBeenCalled();
  });


  // HELPERS

  function respondXML(request, content) {
    header = { "Content-Type": "application/xml;charset=utf-8" };
    body = '<?xml version="1.0" encoding="UTF-8"?>\n';
    body += content;
    request.respond(200, header, body);
  }
});


