#!/bin/bash
cat ../aes.js ../cryptoHelpers.js ../SHA1.js ../MD5.js > crypto.js
perl jsPacker.pl -fsq -e62 -i crypto.js -o crypto.min.js
rm crypto.js
