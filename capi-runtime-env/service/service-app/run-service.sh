#!/bin/bash

APP=service/service-app
WORKDIR=/ws/$APP

# Add the broadcast network route
if ! $(ip ro | grep "224.224.224.245"); then
    ip route add 224.224.224.245 dev eth0
else
    echo "Broadcast route already available..."
fi

# Generate the CAPI core and glue code
cd $WORKDIR
../../cgen/commonapi_core_generator/commonapi-core-generator-linux-x86_64 \
    -d src-gen/core \
    -sk ./fidl/HelloWorld.fidl
../../cgen/commonapi_someip_generator/commonapi-someip-generator-linux-x86_64 \
    -d src-gen/someip \
    ./fidl/HelloWorld.fdepl

# Build the service
if [ -d $WORKDIR/build ]; then
    cmake -Bbuild .
    cmake --build build -j $(nproc)
else
    rm -rf $WORKDIR/build
    cmake -Bbuild .
    cmake --build build -j $(nproc)
fi

COMMONAPI_CONFIG=commonapi4someip.ini LD_LIBRARY_PATH=/usr/local/lib:$PWD/build/ \
VSOMEIP_CONFIGURATION=service.json ./build/HelloWorldService