#include "FLexicon.hpp"
#include "PacketHandler.hpp"

#include <iostream>
#include <fstream>
#include <cstdlib>

#include <x86intrin.h>

static int runFirewall();
static void runParser();
static void runRuleGenerator();
static bool onPacketArrivesBlockingMode(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie);

int main(int argc, char *argv[])
{
    runFirewall();
}

static int runFirewall()
{
    PacketStats stats;

    // IPv4 address of the interface we want to sniff
    std::string interfaceIPAddr = "172.18.0.2";

    // find the interface by IP address
    pcpp::PcapLiveDevice *dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
    if (dev == NULL)
    {
        std::cerr << "Cannot find interface with IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
        return 1;
    }

    // before capturing packets let's print some info about this interface
    std::cout
        << "Interface info:" << std::endl
        << "   Interface name:        " << dev->getName() << std::endl
        << "   Interface description: " << dev->getDesc() << std::endl
        << "   MAC address:           " << dev->getMacAddress() << std::endl
        << "   Default gateway:       " << dev->getDefaultGateway() << std::endl
        << "   Interface MTU:         " << dev->getMtu() << std::endl;

    if (dev->getDnsServers().size() > 0)
        std::cout << "   DNS server:            " << dev->getDnsServers().at(0) << std::endl;

    // open the device before start capturing/sending packets
    if (!dev->open())
    {
        std::cerr << "Cannot open device" << std::endl;
        return 1;
    }

    // start capturing in blocking mode. Give a callback function to call to whenever
    // a packet is captured, the stats object as the cookie and a 10 seconds timeout
    auto &packet_handler = PacketHandler::get_instance();
    dev->startCaptureBlockingMode(onPacketArrivesBlockingMode, &stats, 10);

    // print results
    std::cout << "Results:" << std::endl;
    stats.print_to_console();

    return 0;
}

/**
 * a callback function for the blocking mode capture which is called each time a packet is captured
 */
static bool onPacketArrivesBlockingMode(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie)
{
    auto t1 = __rdtsc();

    // extract the stats object form the cookie
    PacketStats *stats = (PacketStats *)cookie;

    // parsed the raw packet
    pcpp::Packet parsedPacket(packet);

    // collect stats from packet
    stats->consume_packet(parsedPacket);

    auto t2 = __rdtsc();

    std::ofstream res_file;
    res_file.open("chrono_results.csv", std::ios_base::app);
    std::stringstream ss;
    if (!res_file)
        std::cerr << "Error opening file to write" << std::endl;

    ss << (float)((t2 - t1) + 1500000) / 3000000 << "ms," << parsedPacket.getLastLayer()->toString() << "\n";
    // std::cout << ss.str() << std::endl;
    res_file << ss.str();

    // return false means we don't want to stop capturing after this callback
    return false;
}
