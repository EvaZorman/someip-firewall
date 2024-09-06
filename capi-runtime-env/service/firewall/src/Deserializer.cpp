#include "Deserializer.hpp"

#include <endian.h>
#include <limits>
#include <iostream>

/*
    This is assuming that vsomeip is used, which apparently uses little-endian,
    as well as that this code is used on a little-endian CPU
*/

bool Deserializer::_deserialize(uint8_t &value)
{
    if (0 == remaining)
        return false;

    value = *data_position++;
    remaining--;

    return true;
}

bool Deserializer::_deserialize(uint16_t &value)
{
    if (2 > remaining)
        return false;

    uint8_t byte0, byte1;
    byte0 = *data_position++;
    byte1 = *data_position++;
    remaining -= 2;

    value = uint16_t((byte0) << 8 | (byte1));
    return true;
}

bool Deserializer::_deserialize(uint32_t &value, bool omit_last_byte)
{
    if (3 > remaining || (!omit_last_byte && 4 > remaining))
        return false;

    uint8_t byte0 = 0, byte1, byte2, byte3;
    if (!omit_last_byte)
    {
        byte0 = *data_position++;
        remaining--;
    }
    byte1 = *data_position++;
    byte2 = *data_position++;
    byte3 = *data_position++;
    remaining -= 3;

    value = (uint32_t((byte0) << 24 | (byte1) << 16 | (byte2) << 8 | (byte3)));
    return true;
}

bool Deserializer::_deserialize(uint64_t &value, bool omit_last_byte)
{
    if (7 > remaining || (!omit_last_byte && 8 > remaining))
        return false;

    uint8_t byte0 = 0, byte1, byte2, byte3, byte4, byte5, byte6, byte7;
    if (!omit_last_byte)
    {
        byte0 = *data_position++;
        remaining--;
    }
    byte1 = *data_position++;
    byte2 = *data_position++;
    byte3 = *data_position++;
    byte4 = *data_position++;
    byte5 = *data_position++;
    byte6 = *data_position++;
    byte7 = *data_position++;
    remaining -= 7;

    value = (uint64_t(byte0) << 56 | uint64_t(byte1) << 48 | uint64_t(byte2) << 40 | uint64_t(byte3) << 32 | uint64_t(byte4) << 24 | uint64_t(byte5) << 16 | uint64_t(byte6) << 8 | uint64_t(byte7));
    return true;
}

bool Deserializer::deserialize(uint8_t &value)
{
    if (!this->_deserialize(value))
        return false;

    // Constraints checking
    if (value < std::numeric_limits<uint8_t>::min() || value > std::numeric_limits<uint8_t>::max())
        return false;

    return true;
}

bool Deserializer::deserialize(uint16_t &value)
{
    if (!this->_deserialize(value))
        return false;

    // Constraints checking
    if (value < std::numeric_limits<uint16_t>::min() || value > std::numeric_limits<uint16_t>::max())
        return false;

    return true;
}

bool Deserializer::deserialize(uint32_t &value, bool omit_last_byte)
{
    if (!this->_deserialize(value, omit_last_byte))
        return false;

    // Constraints checking
    if (value < std::numeric_limits<uint32_t>::min() || value > std::numeric_limits<uint32_t>::max())
        return false;

    return true;
}

bool Deserializer::deserialize(uint64_t &value, bool omit_last_byte)
{
    if (!this->_deserialize(value, omit_last_byte))
        return false;

    // Constraints checking
    if (value < std::numeric_limits<uint64_t>::min() || value > std::numeric_limits<uint64_t>::max())
        return false;

    return true;
}

bool Deserializer::deserialize(int8_t &value)
{
    uint8_t tmp_val;
    if (!this->_deserialize(tmp_val))
        return false;
    
    value = tmp_val;
    if (value < std::numeric_limits<int8_t>::min() || value > std::numeric_limits<int8_t>::max())
        return false;

    return true;
}

bool Deserializer::deserialize(int16_t &value)
{
    uint16_t tmp_val;
    if (!this->_deserialize(tmp_val))
        return false;

    value = tmp_val;
    // Constraints checking
    if (value < std::numeric_limits<int16_t>::min() || value > std::numeric_limits<int16_t>::max())
        return false;

    return true;
}

bool Deserializer::deserialize(int32_t &value, bool omit_last_byte)
{
    uint32_t tmp_val;
    if (!this->_deserialize(tmp_val, omit_last_byte))
        return false;

    value = tmp_val;

    // Constraints checking
    if (value < std::numeric_limits<int32_t>::min() || value > std::numeric_limits<int32_t>::max())
        return false;

    return true;
}

bool Deserializer::deserialize(int64_t &value, bool omit_last_byte)
{
    uint64_t tmp_val;
    if (!this->_deserialize(tmp_val, omit_last_byte))
        return false;

    value = tmp_val;
    // Constraints checking
    if (value < std::numeric_limits<int64_t>::min() || value > std::numeric_limits<int64_t>::max())
        return false;

    return true;
}

bool Deserializer::deserialize(bool &value)
{
    uint8_t u_value;
    if (!this->_deserialize(u_value))
        return false;

    value = u_value;
    return true;
}

bool Deserializer::deserialize(float &value)
{
    uint32_t tmp_val;
    if (!this->_deserialize(tmp_val, false))
        return false;

    value = tmp_val;
    // Constraints checking
    if (value < std::numeric_limits<float>::min() || value > std::numeric_limits<float>::max())
        return false;
    return true;
}

bool Deserializer::deserialize(double &value)
{
    uint64_t tmp_val;
    if (!this->deserialize(tmp_val, false))
        return false;

    value = tmp_val;
    // Constraints checking
    if (value < std::numeric_limits<double>::min() || value > std::numeric_limits<double>::max())
        return false;

    return true;
}

bool Deserializer::deserialize(std::string &value)
{
    /*  This assumes the default value of 32 bits is used to store the string length
        in the payload right before the string itself. Generally the string structure
        is the following

        | length field | BOM (encoding info)) | string contents |
        ---------------------------------------------------------
            ^                   ^                    ^
      8, 16 or 32 bits |    2 or 3 Bytes      |   length - BOM size

     */
    uint32_t str_length;
    if (!this->deserialize(str_length, false))
    {
        std::cout << "Failed to parse string length!" << str_length << std::endl;
        return false;
    }

    if (str_length > remaining)
    {
        std::cout << "String length " << str_length << " longer than expected " << remaining << std::endl;
        return false;
    }

    try
    {
        value.assign(data_position, data_position + static_cast<size_t>(str_length));
        data_position += static_cast<size_t>(str_length);
        remaining -= str_length;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        return false;
    }

    return true;
}

bool Deserializer::deserialize_someip_header(SomeIpHeader &header)
{
    if (
        this->deserialize(header.serviceID) &&
        this->deserialize(header.methodID) &&
        this->deserialize(header.length, false) &&
        this->deserialize(header.clientID) &&
        this->deserialize(header.sessionID) &&
        this->deserialize(header.protocol_version) &&
        this->deserialize(header.interface_version) &&
        this->deserialize(header.msg_type) &&
        this->deserialize(header.return_code))
        return true;

    return false;
}