#ifndef FLEXICON_HPP
#define FLEXICON_HPP

#include "FInterface.hpp"

#include <set>
#include <memory>
#include <unordered_map>

enum class ArgType
{
    UINT8 = 0,
    UINT16,
    UINT32,
    UINT64,
    INT8,
    INT16,
    INT32,
    INT64,
    INTEGER,
    BOOLEAN,
    FLOAT,
    DOUBLE,
    STRING,
    UNKNOWN
};

class FLexicon
{
private:
    static const std::unordered_map<std::string, ArgType> basic_types;

public:
    static bool is_fidl_keyword(std::string &s);
    static bool is_fdepl_keyword(std::string &s);
    static bool is_basic_type(std::string &s);
    static ArgType get_arg_type(std::string &s);

    static BaseValue create_value(std::string &type, std::string &name);

private:
    inline static const std::set<std::string> fidl_keywords =
        {
            "package",
            "interface",
            // "version",
            // "typeCollection",
            "method",
            "brodcast",
            "in",
            "out"};

    inline static const std::set<std::string> fdepl_keywords =
        {
            "define",
            "SomeIpServiceID",
            "method",
            "SomeIpMethodID"};
};

#endif // FLEXICON_HPP