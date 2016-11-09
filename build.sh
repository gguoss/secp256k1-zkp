#!/bin/sh
./autogen.sh
./configure --enable-experimental --enable-module-rangeproof --enable-module-ecdh --enable-openssl-tests
make
mv tests.exe sdc_zkp.exe

