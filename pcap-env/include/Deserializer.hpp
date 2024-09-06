#ifndef DESERIALIZER_HPP
#define DESERIALIZER_HPP

#include "SomeipDef.hpp"

#include <vector>
#include <cstddef>
#include <string>

class Deserializer
{
protected:
    std::vector<uint8_t> data;
    std::vector<uint8_t>::iterator data_position;
    std::size_t remaining;

public:
    Deserializer(uint8_t *raw_data, std::size_t length)
        : data(raw_data, raw_data + length),
          data_position(data.begin()),
          remaining(length)
    {
    }
    ~Deserializer() = default;

    bool _deserialize(uint8_t &value);
    bool _deserialize(uint16_t &value);
    bool _deserialize(uint32_t &value, bool omit_last_byte);
    bool _deserialize(uint64_t &value, bool omit_last_byte);

    bool deserialize(uint8_t &value);
    bool deserialize(uint16_t &value);
    bool deserialize(uint32_t &value, bool omit_last_byte);
    bool deserialize(uint64_t &value, bool omit_last_byte);
    bool deserialize(int8_t &value);
    bool deserialize(int16_t &value);
    bool deserialize(int32_t &value, bool omit_last_byte);
    bool deserialize(int64_t &value, bool omit_last_byte);
    bool deserialize(bool &value);
    bool deserialize(float &value);
    bool deserialize(double &value);
    bool deserialize(std::string &value);

    bool deserialize_someip_header(SomeIpHeader &header);

    bool is_finished() const { return remaining == 0; }
};

#endif // DESERIALIZER_HPP