# thesis-implementation

## Description
This is the repositody contiaing the source code that was designed and implemented within the scope of the "Implementation of a SOME/IP Firewall with Deep Packet Inspection for automotive use-cases" thesis by Eva Zorman at University of Turku, 2024. 

The repository is split between a realtime environment which provides two docker containers for both a HelloWorld service and client CAPI application and a firewall that can capture the data sent between the two containers, and an environment that contains a SOME/IP firewall implementation that takes PCAP files as input used to benchmark the implementaiton.

The folders in this directory are:

```capi-runtime-env```: This folder contains the CAPI client and service application, respective Dockerfiles to build both, and a firewall implementation that captures pactkets using raw sockets.

```pcap-env```: This folder contains the benchmark implementation of the firewall which takes PCAP files as input instead. At the end, it generates a report including the average and median time taken to process packets.

```someip-generator-config```: This folder contains the configuration used for the SOME/IP Generator tooling, which can be found [here](https://github.com/Egomania/SOME-IP_Generator), if one wishes to re-create the same configuration environment as was used for the DPI testing.

## Installation
A working, running Docker environment needs to be available for an easy usage of the project. If so desired, everything can also be locally installed and used. In that case, look at the requirements in the corresponding Dockerfiles. Recommended OS for this is Ubuntu 22.04 LTS, but any other UNIX distribution should be easily configured as well. 

## Usage
Once docker is installed, a few more steps are necessary for being able to successfully build and run the applications and firewall. A separate docker network is suggested to avoid clustering with already running containers on the default network bridge. This can be done by running

```
docker network create my-network-name
```

After which, the docker images can be built normally, and there are scripts such as `run-client-docker.sh` provided which will take care of running the appropriate docker command to run the container.

***IMPORTANT:***
Make sure that the CAPI service docker container is run first to ensure the IP address (192.168.0.2) is similar to that set in the SOME/IP configuration used. Once the service container is up, everything else can be started as well.

Scripts to build and run the service/client/firewall are also provided, take a look around and explore.

## License
Copyright (c) 2024 Eva Zorman, ehzorm@utu.fi

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


## Project status
The current SOME/IP firewall implementation is at best a PoC with a limited functionality. Currently, only basic FIDL data-types can be parsed and deserialized, including strings. All other complex data-types are not supported. 

There are a number of further improvements that could be added on-top of the current base product. This should by no means be used in any form of production environment. Should an avid reader be more interested in the design, implementation and testing process of this software, more information can be obtained in the published paper.