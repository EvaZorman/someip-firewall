#include "PacketHandler.hpp"
#include "FLexicon.hpp"

#include <SomeIpSdLayer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

#include "stdlib.h"
#include <SystemUtils.h>

#include <iostream>
#include <sstream>

void PacketStats::clear()
{
    parsedPackets = 0;
    droppedPackets = 0;
    droppedDueToFirewallCount = 0;
    droppedDueToSessionIDCount = 0;
    droppedDueToPayloadParsingCount = 0;
}

void PacketHandler::consume_packet(pcpp::Packet &packet, PacketStats &stats, bool print_debug_info)
{
    // if (!packet.isPacketOfType(pcpp::TCP) && !packet.isPacketOfType(pcpp::SomeIP))
    // {
    //     std::cout << "packet not parsable?" << std::endl;
    //     return;
    // }

    pcpp::Layer *layer = packet.getLastLayer();
    if (layer == NULL)
    {
        std::cerr << "Something went wrong, couldn't find last layer" << std::endl;
        return;
    }

    pcpp::IPv4Layer *ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ipLayer == NULL)
    {
        std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;
        return;
    }

    // Within Pcap++, the SomeIpLayer is not yet recognised in TCP messages
    // as such, it is given as a generic payload with the someip packet
    if (layer->getProtocol() == pcpp::GenericPayload)
    {
        SomeIpMessage someip_msg; // = SomeIpMessage(layer->getData());
        Deserializer d = Deserializer(layer->getData(), layer->getDataLen());

        if (!d.deserialize_someip_header(someip_msg.header))
        {
            std::cerr << "Something went wrong with deserializing the header" << std::endl;
            return;
        }

        if (print_debug_info)
            std::cout << someip_msg.to_string() << std::endl;

        RuleAction packet_action = rgen.check_against_ruleset(someip_msg.header.clientID,
                                                            someip_msg.header.serviceID,
                                                            someip_msg.header.methodID);

        if (packet_action == RuleAction::DENY)
        {
            stats.droppedDueToFirewallCount++;
            // For result analysis
            std::cout << "Reason for dropping: Firewall Drop ---" << std::endl;
            std::cout << someip_msg.to_string() << std::endl;
            std::cout << "IP src: " << ipLayer->getSrcIPAddress() << " IP dest: " << ipLayer->getDstIPv4Address() << std::endl;
            
            drop_packet(packet, stats, false, print_debug_info);
            return;
        }
        else if (packet_action == RuleAction::LOG)
        {
            stats.droppedDueToFirewallCount++;
            // For result analysis
            std::cout << "Reason for dropping: Firewall Log ---" << std::endl;
            std::cout << someip_msg.to_string() << std::endl;
            std::cout << "IP src: " << ipLayer->getSrcIPAddress() << " IP dest: " << ipLayer->getDstIPv4Address() << std::endl;
            
            drop_packet(packet, stats, true, print_debug_info);
            return;
        }

        try
        {
            // Check if the messages are following the SOME/IP flow based on the sessionID of the message
            manage_req_queue(someip_msg.header, ipLayer);
        }
        catch (const std::logic_error &e)
        {
            std::cerr << e.what() << '\n';

            stats.droppedDueToSessionIDCount++;
            // For result analysis
            std::cout << "Reason for dropping: Session Queue ---" << std::endl;
            std::cout << someip_msg.to_string() << std::endl;
            std::cout << "IP src: " << ipLayer->getSrcIPAddress() << " IP dest: " << ipLayer->getDstIPv4Address() << std::endl;
            
            drop_packet(packet, stats, true, print_debug_info);
            return;
        }

        if (parse_payload(someip_msg, d, print_debug_info))
        {
            forward_packet(packet, stats, print_debug_info);
            return;
        }
        
        // For result analysis
        std::cout << "Reason for dropping: DPI ---" << std::endl;
        std::cout << someip_msg.to_string() << std::endl;
        std::cout << "IP src: " << ipLayer->getSrcIPAddress() << " IP dest: " << ipLayer->getDstIPv4Address() << std::endl;

        stats.droppedDueToPayloadParsingCount++;
        drop_packet(packet, stats, false, print_debug_info);
    }
    // UDP based SomeIP-SD messages have a different structure compared to the generic SOMEIP header
    else if (layer->getProtocol() == pcpp::SomeIP)
    {
        auto someipsd_layer = packet.getLayerOfType<pcpp::SomeIpSdLayer>();
        if (someipsd_layer == NULL)
        {
            std::cerr << "Something went wrong, couldn't find SOME/IP-SD layer" << std::endl;
            return;
        }

        // For now, no parsing of SOME/IP-SD is supported, only check the firewall rules
        auto someip_hdr = someipsd_layer->getSomeIpHeader();

        RuleAction packet_action = rgen.check_against_ruleset(someip_hdr->clientID,
                                                            someip_hdr->serviceID,
                                                            someip_hdr->methodID);

        if (packet_action == RuleAction::DENY)
        {
            stats.droppedDueToFirewallCount++;
            drop_packet(packet, stats, false, print_debug_info);
        }
        else if (packet_action == RuleAction::LOG)
        {
            stats.droppedDueToFirewallCount++;
            drop_packet(packet, stats, true, print_debug_info);
        }
        else
            forward_packet(packet, stats, print_debug_info);
    }
}

void PacketHandler::drop_packet(pcpp::Packet &packet, PacketStats &stats, bool log, bool debug_info)
{
    if (debug_info)
        std::cout << "Dropping SOME/IP packet" << std::endl;
    stats.droppedPackets++;
}

void PacketHandler::forward_packet(pcpp::Packet &packet, PacketStats &stats, bool debug_info)
{
    if (debug_info)
        std::cout << "Forwarding SOME/IP packet" << std::endl;
    stats.parsedPackets++;
}

bool PacketHandler::parse_payload(SomeIpMessage &message, Deserializer &d, bool debug_info)
{
    if (message.header.msg_type == someip_msg_notification)
    {
        if (debug_info)
            std::cerr << "NOTIFICATION SOME/IP message parsing currently not supported." << std::endl;
        return true;
    }

    for (auto &m : InterfaceParser::get_instance().get_models())
    {
        // Find the method matching in serviceID and methodID
        auto matched_method_ptr = m.find_method(message.header.serviceID, message.header.methodID);
        if (matched_method_ptr == NULL)
        {
            if (debug_info)
                std::cout << "Couldn't find any matches in model " << m.get_name() << std::endl;
            continue;
        }

        // If the method contains complex args, we cannot parse it for now
        if (!matched_method_ptr->is_parsable)
        {
            if (debug_info)
                std::cerr << "Method " << matched_method_ptr->get_name() << " is not parsable" << std::endl;
            return true;
        }

        // Based on the message type value, we can guess if we need to parse in or out args
        if (message.header.msg_type == someip_msg_request || message.header.msg_type == someip_msg_request_no_return)
        {
            for (auto arg : matched_method_ptr->in_args)
            {
                if (!PacketHandler::parse_arg_based_on_type(arg, d))
                    return false;
            }
            if (!d.is_finished())
                return false;

            return true;
        }
        else if (message.header.msg_type == someip_msg_response || message.header.msg_type == someip_msg_error)
        {
            for (auto arg : matched_method_ptr->out_args)
            {
                if (!PacketHandler::parse_arg_based_on_type(arg, d))
                    return false;
            }
            if (!d.is_finished())
                return false;

            return true;
        }
    }

    return false;
}

void PacketHandler::manage_req_queue(SomeIpHeader header, pcpp::IPv4Layer *ipLayer)
{
    auto is_header_equal = [header](SomeIpHeader &h)
    { return h.serviceID == header.serviceID &&
             h.methodID == header.methodID &&
             h.clientID == header.clientID &&
             h.sessionID == header.sessionID; };

    // NOTIFICATION and REQUEST_NO_RESPONSE messages are not added to the queue as they require no answer
    if (header.msg_type == someip_msg_request_no_return || header.msg_type == someip_msg_notification)
        return;
    // REQUEST messages are added to the queue as they require an answer
    else if (header.msg_type == someip_msg_request)
    {
        if (requests_awaiting_resp.empty())
        {
            requests_awaiting_resp.push_back(header);
            return;
        }

        // Check if REQUEST with same sessionID is already in the queue
        auto it = std::find_if(requests_awaiting_resp.begin(), requests_awaiting_resp.end(), is_header_equal);
        if (it != requests_awaiting_resp.end())
        {
            std::stringstream ss;
            ss << "SOME/IP request was already present for sessionID of "
               << (int)header.sessionID
               << " for message type "
               << (int)header.msg_type;
            throw std::logic_error(ss.str());
        }
        requests_awaiting_resp.push_back(header);
    }
    // If the message is a RESPONSE or ERROR, there needs to be a request already present in the queue to be accepted
    else if (header.msg_type == someip_msg_response || header.msg_type == someip_msg_error)
    {
        if (requests_awaiting_resp.empty())
        {
            std::stringstream ss;
            ss << "(1) No matching request was found for sessionID "
               << (int)header.sessionID
               << " of type "
               << (int)header.msg_type
               << " from clientID "
               << (int)header.clientID
               << " and source ip addr "
               << ipLayer->getSrcIPAddress();
            throw std::logic_error(ss.str());
        }

        // Check if there is any REQUEST with same sessionID present
        auto it = std::find_if(requests_awaiting_resp.begin(), requests_awaiting_resp.end(), is_header_equal);
        if (it != requests_awaiting_resp.end())
            requests_awaiting_resp.erase(it);
        else
        {
            std::stringstream ss;
            ss << "(2) No matching request was found for sessionID "
               << (int)header.sessionID
               << " of type "
               << (int)header.msg_type
               << " from clientID "
               << (int)header.clientID
               << " and source ip addr "
               << ipLayer->getSrcIPAddress();
            throw std::logic_error(ss.str());
        }
    }
}

bool PacketHandler::parse_arg_based_on_type(BaseValue &base_value, Deserializer &d)
{
    std::string arg_type = base_value.get_type();
    ArgType a = FLexicon::get_arg_type(arg_type);
    bool res = false;

    if (a == ArgType::UINT8)
    {
        uint8_t parsed_uint8;
        res = d.deserialize(parsed_uint8);
    }
    else if (a == ArgType::UINT16)
    {
        uint16_t parsed_uint16;
        res = d.deserialize(parsed_uint16);
    }
    else if (a == ArgType::UINT32)
    {
        uint32_t parsed_uint32;
        res = d.deserialize(parsed_uint32, false);
    }
    else if (a == ArgType::UINT64)
    {
        uint64_t parsed_uint64;
        res = d.deserialize(parsed_uint64, false);
    }
    else if (a == ArgType::INT8)
    {
        int8_t parsed_int8;
        res = d.deserialize(parsed_int8);
    }
    else if (a == ArgType::INT16)
    {
        int16_t parsed_int16;
        res = d.deserialize(parsed_int16);
    }
    else if (a == ArgType::INT32)
    {
        int32_t parsed_int32;
        res = d.deserialize(parsed_int32, false);
    }
    else if (a == ArgType::INT64)
    {
        int64_t parsed_int64;
        res = d.deserialize(parsed_int64, false);
    }
    else if (a == ArgType::INTEGER)
    {
        int parsed_int;
        res = d.deserialize(parsed_int, false);
    }
    else if (a == ArgType::BOOLEAN)
    {
        bool parsed_bool;
        res = d.deserialize(parsed_bool);
    }
    else if (a == ArgType::FLOAT)
    {
        float parsed_float;
        res = d.deserialize(parsed_float);
    }
    else if (a == ArgType::DOUBLE)
    {
        double parsed_double;
        res = d.deserialize(parsed_double);
    }
    else if (a == ArgType::STRING)
    {
        std::string parsed_s;
        res = d.deserialize(parsed_s);
    }

    return res;
}

PacketHandler &PacketHandler::get_instance()
{
    static auto &&p_handler = PacketHandler();
    return (p_handler);
}

// void PacketHandler::on_packet_arrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie)
// {
//     PacketStats *stats = (PacketStats *)cookie;
//     pcpp::Packet parsedPacket(packet);
//     stats->consume_packet(parsedPacket);
// }
