#ifndef INTERFACE_PARSER_HPP
#define INTERFACE_PARSER_HPP

#include "FInterface.hpp"

#include <filesystem>
#include <string_view>
#include <set>

class InterfaceParser
{
private:
    // std::set<std::string> all_methods;
    std::vector<FModel> fmodels;

    InterfaceParser()
    {
        _parse_files();
        print();
    };

    void _parse_files();
    void _parse_fidl(std::filesystem::path path, FModel &model);
    void _parse_fdepl(std::filesystem::path path, FModel &model);
    // void _add_method(std::string &m_name, std::vector<std::unique_ptr<BaseValue>> &args, bool in_args);

public:
    ~InterfaceParser() = default;
    static InterfaceParser &get_instance();
    std::vector<FModel> &get_models() { return fmodels; }

    void print();
    // std::vector<std::string> get_parsable_methods();
    // FMethod * get_method(std::string_view m_name);
};

#endif // INTERFACE_PARSER_HPP