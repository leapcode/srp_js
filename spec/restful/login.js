describe("Login", function() {

  it("has an identify function", function() {
    var srp = new SRP(jqueryRest());
    expect(typeof srp.identify).toBe('function');
  });

  describe("(INTEGRATION)", function (){
    // these need to be the same as in the spec runner:
    var login = "testuser";
    var password = "password";
    // a valid auth attempt for the user / password given in the spec runner:
    var a = 'a5cccf937ea1bf72df5cf8099442552f5664da6780a75436d5a59bc77a8a9993';
    var A = 'e67d222244564ccd2e37471f226b999a4e987f3d494c7d80e0d36169efd6c6c6d857a96924c25fc165e5e9b0212a31c30701ec376dc32e36be00bbcd6d2104789d368af984e26fc094374f90ee5746478f14cec45c7e131a3cbce15fe79e98894213dac4e63c3f73f644fe25aa8707bc58859dfd1b36972e4e34169db2622899';
    // just for the sake of having a complete set of test vars:
    var b = '6aa5c88d1877af9907ccefad31083e1102a7121dc04706f681f66c8680fb7f05'; 
    var B = 'd56a80aaafdf9f70598b5d1184f122f326a333fafd37ab76d6f7fba4a9c4ee59545be056335150bd64f04880bc8e76949469379fe9de17cf6f36f3ee11713d05f63050486bc73c545163169999ff01b55c0ca4e90d8856a6e3d3a6ffc70b70d993a5308a37a5c2399874344e083e72b3c9afa083d312dfe9096ea9a65023f135';
    var salt = '628365a0';
    var K = 'db6ec0bdab81742315861a828323ff492721bdcd114077a4124bc425e4bf328b';
    var M = '640e51d5ac5461591c31811221261f0e0eae7c08ce43c85e9556adbd94ed8c26';
    var M2 = '49e48f8ac8c4da0e8a7374f73eeedbee2266e123d23fc1be1568523fc9c24b1e';
    var V = '6f5fb78184161f4191babaf1a700ff70e4d261054d002466d05f2ec2b45fc8807dbd7ce25dc3c882331eb8bf72a22caf2868e3438477be7ab151d3281d00aa1a9fc5cb6a725abd99e11882f77d52b56b83f95c0ba0b8fbbf4ee1fbb445c35adb5d1aaa48ba761c4a4417f6bb821fb61956c919e47740b316b960653303fe7190';
    var A_, callback;


    beforeEach(function() {
      this.srp = new SRP(jqueryRest());

      specHelper.setupFakeXHR.apply(this);

      A_ = this.srp.session.calculateAndSetA(a)
      this.srp.success = sinon.spy();
    });

    afterEach(function() {
      this.xhr.restore();
    });

    it("starts with the right A", function(){
      expect(A_).toBe(A);
    });

    it("starts with the right verifier", function(){
      expect(this.srp.session.getV().toString(16)).toBe(V);
    });

    it("calculates the right key", function(){
      this.srp.session.calculations(salt, B);
      expect(this.srp.session.key()).toBe(K);
    });

    it("works with JSON responses", function(){
      this.srp.identify();

      this.expectRequest('sessions', 'login=' +login+ '&A=' +A, 'POST');
      this.respondJSON({salt: salt, B: B});
      this.expectRequest('sessions/'+login, 'client_auth='+M, 'PUT');
      this.respondJSON({M2: M2});

      expect(this.srp.success).toHaveBeenCalled();
    });
    
    it("rejects B = 0", function(){
      this.srp.error = sinon.spy();
      this.srp.identify();

      this.expectRequest('sessions', 'login=' +login+ '&A=' +A, 'POST');
      this.respondJSON({salt: salt, B: 0});
      // aborting if B=0
      expect(this.requests).toEqual([]);
      expect(this.srp.error).toHaveBeenCalled();
    });
  });


});
