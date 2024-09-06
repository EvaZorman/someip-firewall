#include "PacketHandler.hpp"

#include <iostream>
#include <sstream>
#include <fstream>
#include "stdlib.h"
#include "PcapFileDevice.h"


// #include <x86intrin.h>
#include <time.h> 
#include <filesystem>
#include <bits/stdc++.h>

static bool onPacketArrivesBlockingMode(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie);

int main(int argc, char *argv[])
{
    bool print_debug_info = false;
    char const *debug_env = getenv("SOMEIP_FIREWALL_DEBUG");
    if (debug_env != NULL)
        print_debug_info = true;

    std::filesystem::path in_file = "test/test_input.pcap";
    char const *in_file_env = getenv("SOMEIP_FIREWALL_IN_FILE");
    if (in_file_env != NULL)
        in_file = std::string(in_file_env);
    
    std::filesystem::path out_file = "test/test_input.results";
    char const *out_file_env = getenv("SOMEIP_FIREWALL_OUT_FILE");
    if (out_file_env != NULL)
        out_file = std::string(out_file_env);

    // Pcap++ can load info from a .pcap file
    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(in_file);

    // verify that a reader interface was indeed created
    if (reader == NULL)
    {
        std::cerr << "Cannot determine reader for file type" << std::endl;
        return 1;
    }

    // open the reader for reading
    if (!reader->open())
    {
        std::cerr << "Cannot open input pcap file " << in_file << std::endl;
        return 1;
    }

    pcpp::RawPacket rawPacket;
    PacketStats stats;
    PacketHandler &p_handler = PacketHandler::get_instance();

    int packet_count = 0;
    std::vector<clock_t> cpu_cycles;

    while (reader->getNextPacket(rawPacket))
    {
        pcpp::Packet parsedPacket(&rawPacket);

        clock_t t1 = clock();
        p_handler.consume_packet(parsedPacket, stats, print_debug_info);
        clock_t t2 = clock();

        packet_count++;
        cpu_cycles.push_back(t2 - t1);
    }

    std::stringstream ss;
    ss << "---------------------------------------------------------" << std::endl
       << "Number of received packets: " << packet_count << std::endl
       << "Number of parsed packets: " << stats.parsedPackets << std::endl
       << "Number of dropped packets: " << stats.droppedPackets << std::endl
       << "\tDue to firewall rules: " << stats.droppedDueToFirewallCount << std::endl
       << "\tDue to sessionID mismatch: " << stats.droppedDueToSessionIDCount << std::endl
       << "\tDue to payload parsing: " << stats.droppedDueToPayloadParsingCount << std::endl;

    auto m = cpu_cycles.begin() + cpu_cycles.size() / 2;
    std::nth_element(cpu_cycles.begin(), m, cpu_cycles.end());
    ss << "Median clicks: " << cpu_cycles[cpu_cycles.size() / 2] << std::endl;
    ss << "Median time: " << (float)cpu_cycles[cpu_cycles.size() / 2]/CLOCKS_PER_SEC << std::endl;
    auto avg = std::accumulate(cpu_cycles.begin(), cpu_cycles.end(), 0.0) / cpu_cycles.size();
    ss << "Average clicks: " << avg << std::endl;
    ss << "Average time: " << (float)avg/CLOCKS_PER_SEC << std::endl;
    ss << "Max & min time: " << cpu_cycles[0]/CLOCKS_PER_SEC << " & " 
       << cpu_cycles[cpu_cycles.size()-1]/CLOCKS_PER_SEC << std::endl;
    // ss << "In miliseconds: " << (float)(((cpu_cycles[cpu_cycles.size() / 2]) + 1500000) / 3000000) << "ms" << std::endl;
    
    // std::ofstream outFile;
    // outFile.open(out_file);
    // outFile << ss.rdbuf();
    std::cout << ss.str() << std::endl;
}