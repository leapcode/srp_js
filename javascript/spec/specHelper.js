var specHelper = (function() {
  // HELPERS

  function respondXML(request, content) {
    header = { "Content-Type": "application/xml;charset=utf-8" };
    body = '<?xml version="1.0" encoding="UTF-8"?>\n';
    body += content;
    request.respond(200, header, body);
  }
  
  var originalBigInteger = BigInteger;
  
  return {
    respondXML: respondXML
  }

})();
