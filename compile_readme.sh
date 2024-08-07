#!/bin/sh

if ! command -v markdown-toc &> /dev/null
then
  echo 'Error: `markdown-toc` is not available'
  echo 'Install it via `npm install -g markdown-toc`'
  exit 1
fi

echo '
<!-- 
  DO NOT EDIT THIS FILE!
  This file was generated automatically via a script. Please,
  edit `README-tpl.md` instead.
-->
' > README.md

cat README-tpl.md \
  | sed -e '/GO_EXAMPLE/{r go/sign.go' -e 'd}' \
  >> README.md

markdown-toc -i README.md
