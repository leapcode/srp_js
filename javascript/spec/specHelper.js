var specHelper = (function() {
  // HELPERS

  function respondXML(request, content) {
    header = { "Content-Type": "application/xml;charset=utf-8" };
    body = '<?xml version="1.0" encoding="UTF-8"?>\n';
    body += content;
    request.respond(200, header, body);
  }

  function respondJSON(request, object) {
    header = { "Content-Type": "application/json;charset=utf-8" };
    body = JSON.stringify(object);
    request.respond(200, header, body);
  } 

  return {
    respondJSON: respondJSON,
    respondXML: respondXML
  }

})();
