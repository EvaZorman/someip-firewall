#!/bin/bash

# Build the firewall
if [ -d build ]; then
    cmake -Bbuild .
    cmake --build build -j $(nproc)
else
    rm -rf build
    cmake -Bbuild .
    cmake --build build -j $(nproc)
fi

