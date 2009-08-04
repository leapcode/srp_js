#!/bin/bash
cat ../SHA1.js ../MD5.js > hash.js
perl jsPacker.pl -fsq -e62 -i hash.js -o hash.min.js
rm hash.js
