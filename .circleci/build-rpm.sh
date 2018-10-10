#!/bin/sh
name='go-audit'
version=$(cat .circleci/VERSION.txt)
iteration="$(date +%Y%m%d%H%M).git$(git rev-parse --short HEAD)"  # datecode + git sha-ref: "201503020102.gitef8e0fb"
arch='x86_64'
url="https://github.com/pantheon-systems/${name}"
vendor='Pantheon'
description='a kernel auditing shipper built in go'
install_prefix="/opt/${name}"

filepath=$name
if [ -d "$CIRCLE_ARTIFACTS" ] ; then
  filepath="$CIRCLE_ARTIFACTS/$name"
fi

fpm -s dir -t rpm \
    --name "${name}" \
    --version "${version}" \
    --iteration "${iteration}" \
    --architecture "${arch}" \
    --url "${url}" \
    --vendor "${vendor}" \
    --description "${description}" \
    README.md=$install_prefix/README.md \
    .circleci/VERSION.txt=$install_prefix/VERSION.txt \
    $filepath=$install_prefix


if [ -d "$CIRCLE_ARTIFACTS" ] ; then
  cp ./*.rpm "$CIRCLE_ARTIFACTS"
fi
