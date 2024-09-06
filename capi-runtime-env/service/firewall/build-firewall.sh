#!/bin/bash

APP=service/firewall
WORKDIR=/ws/$APP

# Build the firewall
if [ -d $WORKDIR/build ]; then
    cmake -Bbuild .
    cmake --build build -j $(nproc)
else
    rm -rf $WORKDIR/build
    cmake -Bbuild .
    cmake --build build -j $(nproc)
fi

