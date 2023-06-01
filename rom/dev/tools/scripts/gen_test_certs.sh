#!/usr/bin/bash

# Licensed under the Apache-2.0 license

set -e

cargo test -p caliptra-image-fake-keys test_write_lms_keys -- --ignored >/dev/null

for value in {0..3}
do
  openssl ecparam -name secp384r1 -genkey -noout -out $1/vnd-priv-key-$value.pem
  openssl ec -in  $1/vnd-priv-key-$value.pem -pubout -out $1/vnd-pub-key-$value.pem
done

openssl ecparam -name secp384r1 -genkey -noout -out $1/own-priv-key.pem
openssl ec -in  $1/own-priv-key.pem -pubout -out $1/own-pub-key.pem

