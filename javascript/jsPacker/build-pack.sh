#!/bin/bash
cat ../SHA256.js ../prng4.js ../rng.js ../jsbn.js ../jsbn2.js ../srp.js > utils.js
perl jsPacker.pl -fsq -e62 -i utils.js -o srp.min.js
rm utils.js

echo "var srpPath = (function(){\nvar scr=document.getElementsByTagName('script');\nreturn scr[scr.length-1].getAttribute(\"src\");\n})();" >> srp.min.js
