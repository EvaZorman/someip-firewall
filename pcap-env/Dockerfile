FROM ubuntu:22.04

LABEL maintainer="ehzorm@utu.fi"
LABEL version="0.1"
LABEL description="This is a Docker image for a SOME/IP firewall that uses PCAP files"

ARG DEBIAN_FRONTEND=noninteractive

ENV APP_WORKDIR=/ws/firewall

ENV LD_LIBRARY_PATH=/usr/local/lib:${APP_WORKDIR}/build

RUN apt-get update -y --fix-missing
RUN apt-get install -y build-essential \
                       cmake \
                       cmake-qt-gui \
                       default-jre \
                       expat \
                       git \
                       iproute2 \
                       jq \
                       libboost-all-dev \
                       libexpat-dev \
                       libpcap-dev \
                       sudo \
                       unzip \
		       valgrind \
                       wget \
                       vim
WORKDIR /ws

# Install the CommonAPI runtime library
RUN git clone https://github.com/GENIVI/capicxx-core-runtime.git
RUN cd capicxx-core-runtime/ && \
    cmake -Bbuild . && \
    cmake --build build/ -j $(nproc) --target install

# Instal vsomeip GENIVI SOME/IP stack
RUN git clone https://github.com/COVESA/vsomeip.git
RUN cd vsomeip && \
    cmake -Bbuild -DENABLE_SIGNAL_HANDLING=1 -DDIAGNOSIS_ADDRESS=0x10 . && \
    cmake --build build -j $(nproc) --target install

# Build the CommonAPI SOME/IP Runtime Library
RUN git clone https://github.com/GENIVI/capicxx-someip-runtime.git
RUN cd capicxx-someip-runtime && \
    cmake -Bbuild -DUSE_INSTALLED_COMMONAPI=OFF . && \
    cmake --build build -j $(nproc) --target install

# Install PcapPlusPlus library
RUN mkdir pcapp && \
    wget https://github.com/seladb/PcapPlusPlus/archive/v23.09.tar.gz && \
    tar --gzip -xf v23.09.tar.gz -C /ws/pcapp --strip-components 1 && \
    cd pcapp && \
    cmake -S . -B build && \
    cmake --build build -j $(nproc) --target install

# Get the CommonAPI core and SOME/IP code generators
#RUN mkdir cgen && \
#    cd cgen && \
#    wget https://github.com/GENIVI/capicxx-core-tools/releases/download/3.2.14/commonapi_core_generator.zip && \
#    unzip commonapi_core_generator.zip -d commonapi_core_generator/ && \
#    wget https://github.com/GENIVI/capicxx-someip-tools/releases/download/3.2.14/commonapi_someip_generator.zip && \
#    unzip commonapi_someip_generator.zip -d commonapi_someip_generator/

#USER 1000
