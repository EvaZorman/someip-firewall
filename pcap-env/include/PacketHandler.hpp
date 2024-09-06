#ifndef PACKET_HANDLER_HPP
#define PACKET_HANDLER_HPP

#include "SomeipDef.hpp"
#include "RuleGenerator.hpp"
#include "InterfaceParser.hpp"
#include "Deserializer.hpp"

#include "stdlib.h"
#include <PcapLiveDeviceList.h>
#include <SystemUtils.h>
#include <IPv4Layer.h>

#include <vector>

struct PacketStats
{
    long parsedPackets;
    long droppedPackets;
    long droppedDueToFirewallCount;
    long droppedDueToSessionIDCount;
    long droppedDueToPayloadParsingCount;

    PacketStats() { clear(); }
    ~PacketStats() = default;

    void clear();

    void print_to_console();
};

class PacketHandler
{
protected:
    InterfaceParser &fparser = InterfaceParser::get_instance();
    RuleGenerator &rgen = RuleGenerator::get_instance();

    std::vector<SomeIpHeader> requests_awaiting_resp;
    
    PacketHandler() = default;

public:
    ~PacketHandler() = default;
    static PacketHandler &get_instance();

    void consume_packet(pcpp::Packet &packet, PacketStats &stats, bool print_debug_info);
    void drop_packet(pcpp::Packet &packet, PacketStats &stats, bool log, bool debug_info);
    void forward_packet(pcpp::Packet &packet, PacketStats &stats, bool debug_info);
    bool parse_payload(SomeIpMessage &message, Deserializer &d, bool debug_info);

    void manage_req_queue(SomeIpHeader header, pcpp::IPv4Layer* ipLayer);

    // static void on_packet_arrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie);
    static bool parse_arg_based_on_type(BaseValue &base_value, Deserializer &d);
};

#endif // PACKET_HANDLER_HPP