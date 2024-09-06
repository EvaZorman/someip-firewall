#ifndef SOMEIP_DEF_HPP
#define SOMEIP_DEF_HPP

#include <cstddef>
#include <string>
#include <sstream>
#include <iostream>

#pragma pack(push, 1)
struct SomeIpHeader
{
    uint16_t serviceID = 0;
    uint16_t methodID = 0;
    uint32_t length = 0;
    uint16_t clientID = 0;
    uint16_t sessionID = 0;
    uint8_t protocol_version = 0;
    uint8_t interface_version = 0;
    uint8_t msg_type = 0;
    uint8_t return_code = 0;
};
#pragma pack(pop)

// The Message Type field values for SOME/IP as set by AUTOSAR standard
static const uint8_t someip_msg_request = 0x00;
static const uint8_t someip_msg_request_no_return = 0x01;
static const uint8_t someip_msg_notification = 0x02;
static const uint8_t someip_msg_response = 0x80;
static const uint8_t someip_msg_error = 0x81;

// // the message type field values for some/ip-tp as set by autosar standard
// static const uint8_t someip_msg_tp_request = 0x20;
// static const uint8_t someip_msg_tp_request_no_return = 0x21;
// static const uint8_t someip_msg_tp_notification = 0x22;
// static const uint8_t someip_msg_tp_response = 0xa0;
// static const uint8_t someip_msg_tp_error = 0xa1;

class SomeIpMessage
{
public:
    SomeIpHeader header;
    uint8_t *payload;

    SomeIpMessage() = default;
    ~SomeIpMessage() = default;

    uint8_t *get_payload() const { return payload; }

    std::size_t get_payload_length()
    {
        return header.length - (sizeof(header.clientID) + sizeof(header.sessionID) +
                                sizeof(header.protocol_version) + sizeof(header.interface_version) +
                                sizeof(header.msg_type) + sizeof(header.return_code));
    }

    bool is_header_empty() { return header.serviceID == 0 &&
                                    header.methodID == 0 &&
                                    header.length == 0 &&
                                    header.clientID == 0 &&
                                    header.sessionID == 0 &&
                                    header.protocol_version == 0 &&
                                    header.interface_version == 0 &&
                                    header.msg_type == 0 &&
                                    header.return_code == 0;}

    std::string to_string()
    {
        std::ostringstream ss;
        ss << "SOME/IP Header:";
        ss << "\n\tServiceID: " << header.serviceID;
        ss << "\n\tMethodID: " << header.methodID;
        ss << "\n\tLength: " << header.length;
        ss << "\n\tClientID: " << header.clientID;
        ss << "\n\tSessionID: " << header.sessionID;
        ss << "\n\tProtocol Version: " << int(header.protocol_version);
        ss << "\n\tInterface Version: " << int(header.interface_version);
        ss << "\n\tMessage Type: " << int(header.msg_type);
        ss << "\n\tReturn Code: " << int(header.return_code);
        return ss.str();
    }
};

#endif // SOMEIP_DEF_HPP