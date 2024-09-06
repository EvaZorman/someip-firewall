cmake_minimum_required (VERSION 3.13)
project(SOMEIP-firewall)

set (CMAKE_CXX_FLAGS "-g -std=c++17")
add_compile_options (-O0)

set (APP_NAME someip-firewall)

set(Boost_USE_STATIC_LIBS OFF) 
set(Boost_USE_MULTITHREADED OFF)  
set(Boost_USE_STATIC_RUNTIME OFF) 

add_executable("${APP_NAME}"
  src/Firewall.cpp
  src/InterfaceParser.cpp
  src/FLexicon.cpp
  src/FInterface.cpp
  src/RuleGenerator.cpp
  src/PacketHandler.cpp
  src/Deserializer.cpp
)

find_package(PcapPlusPlus REQUIRED)
find_package(Boost COMPONENTS regex) 
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
endif()

target_include_directories("${APP_NAME}" PRIVATE include)
target_link_libraries("${APP_NAME}" 
  PUBLIC PcapPlusPlus::Pcap++ 
  PcapPlusPlus::Common++
  PcapPlusPlus::Packet++
  ${Boost_LIBRARIES}
)
