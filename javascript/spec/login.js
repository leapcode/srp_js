describe("Login", function() {

  it("has an identify function", function() {
    var srp = new SRP();
    expect(typeof srp.identify).toBe('function');
  });

  describe("Successfull Login (INTEGRATION)", function (){
    // a valid auth attempt for the user / password given in the spec runner:
    var a = 'af141ae6';
    var B = '887005895b1f5528b4e4dfdce914f73e763b96d3c901d2f41d8b8cd26255a75';
    var salt = '5d3055e0acd3ddcfc15';
    var M = 'be6d7db2186d5f6a2c55788479b6eaf75229a7ca0d9e7dc1f886f1970a0e8065'
    var M2 = '2547cf26318519090f506ab73a68995a2626b1c948e6f603ef9e1b0b78bf0f7b';
    var A, callback;


    beforeEach(function() {
      this.srp = new SRP();
      A = this.srp.calculateAndSetA(a);

      specHelper.setupFakeXHR.apply(this);

      this.srp.success = sinon.spy();
    });

    afterEach(function() {
      this.xhr.restore();
    });

    it("works with XML responses", function(){
      this.srp.identify();
      expect(this.requests.length).toBe(1);
      expect(this.requests[0].url).toBe("handshake/");
      expect(this.requests[0].requestBody).toBe("I=user&A=" + A);
      specHelper.respondXML(this.requests[0], "<r s='"+salt+"' B='"+B+"' />");
      expect(this.requests.length).toBe(2);
      expect(this.requests[1].url).toBe("authenticate/");
      expect(this.requests[1].requestBody).toBe("M=" + M);
      specHelper.respondXML(this.requests[1], "<M>"+M2+"</M>");

      expect(this.srp.success).toHaveBeenCalled();
      expect(window.location.hash).toBe("#logged_in")
    });

    it("works with JSON responses", function(){
      this.srp.identify();

      expect(this.requests.length).toBe(1);
      expect(this.requests[0].url).toBe("handshake/");
      expect(this.requests[0].requestBody).toBe("I=user&A=" + A);
      specHelper.respondJSON(this.requests[0], {s: salt, B: B});
      expect(this.requests.length).toBe(2);
      expect(this.requests[1].url).toBe("authenticate/");
      expect(this.requests[1].requestBody).toBe("M=" + M);
      specHelper.respondJSON(this.requests[1], {M: M2});

      expect(this.srp.success).toHaveBeenCalled();
      expect(window.location.hash).toBe("#logged_in")
    });
  });


});

