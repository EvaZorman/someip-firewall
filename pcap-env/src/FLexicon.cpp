#include "FLexicon.hpp"

#include <iostream>
#include <stdexcept>

const std::unordered_map<std::string, ArgType> FLexicon::basic_types{
    {"UInt8", ArgType::UINT8},
    {"UInt16", ArgType::UINT16},
    {"UInt32", ArgType::UINT32},
    {"UInt64", ArgType::UINT64},
    {"Int8", ArgType::INT8},
    {"Int16", ArgType::INT16},
    {"Int32", ArgType::INT32},
    {"Int64", ArgType::INT64},
    {"Integer", ArgType::INTEGER},
    {"Boolean", ArgType::BOOLEAN},
    {"Float", ArgType::FLOAT},
    {"Double", ArgType::DOUBLE},
    {"String", ArgType::STRING}};

/*static*/
bool FLexicon::is_fidl_keyword(std::string &s)
{
    return fidl_keywords.find(s) != fidl_keywords.end();
}

/*static*/
bool FLexicon::is_fdepl_keyword(std::string &s)
{
    return fdepl_keywords.find(s) != fdepl_keywords.end();
}

/*static*/
bool FLexicon::is_basic_type(std::string &s)
{
    auto it = basic_types.find(s);
    return it != basic_types.end();
}

/*static*/
ArgType FLexicon::get_arg_type(std::string &s)
{
    auto it = basic_types.find(s);
    if ( it == basic_types.end())
        return ArgType::UNKNOWN;
    
    return it->second;
}


/*static*/
BaseValue FLexicon::create_value(std::string &type, std::string &name)
{
    if (!FLexicon::is_basic_type(type))
    {
        throw std::invalid_argument(type);
    }

    return BaseValue(type, name);
}
