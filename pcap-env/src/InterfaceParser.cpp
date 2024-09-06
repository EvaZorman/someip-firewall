#include "InterfaceParser.hpp"
#include "FLexicon.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <exception>

void lstrip(std::string &str)
{
    if (str.length() == 0)
    {
        return;
    }

    auto start_it = str.begin();
    auto end_it = str.rbegin();
    while (std::isspace(*start_it))
    {
        ++start_it;
        if (start_it == str.end())
            break;
    }
    int start_pos = start_it - str.begin();
    int end_pos = end_it.base() - str.begin();
    str = start_pos <= end_pos ? std::string(start_it, end_it.base()) : "";
}

size_t find_nth_space(const std::string &str, int nth)
{
    size_t pos = -1;
    int cnt = 0;

    while (cnt != nth)
    {
        pos += 1;
        pos = str.find_first_of(" ", pos);
        if (pos == std::string::npos)
            return -1;
        cnt++;
    }
    return pos;
}

InterfaceParser &InterfaceParser::get_instance()
{
    static auto &&i_parser = InterfaceParser();
    return (i_parser);
}

void InterfaceParser::_parse_files()
{
    std::vector<std::string> parsed_files;

    // Loading can be overwritten by using SOMEIP_FIREWALL_RULES env. variable.
    std::filesystem::path path = "fidl";
    char const *temp = getenv("SOMEIP_FIDL_FOLDER");
    if (temp != NULL)
        path = std::string(temp);

    for (auto const &dir_entry : std::filesystem::recursive_directory_iterator(path))
    {
        std::string file_name = dir_entry.path().stem();
        if (std::find(parsed_files.begin(), parsed_files.end(), file_name) != parsed_files.end())
            continue;

        try
        {
            FModel model = FModel(file_name);

            std::string p = dir_entry.path().parent_path().string() + "/" + file_name;
            _parse_fidl(p + ".fidl", model);
            _parse_fdepl(p + ".fdepl", model);

            parsed_files.push_back(file_name);
            fmodels.push_back(model);
        }
        catch (const std::runtime_error &e)
        {
            std::cerr << e.what() << '\n';
        }
    }
}

void InterfaceParser::_parse_fidl(std::filesystem::path path, FModel &model)
{
    /*
        Parse a FIDL file, only looking at the values that are of importance to the firewall.
        [Contstraint] The FIDL file must be well-formed
    */
    std::ifstream ifile(path);
    if (!ifile)
    {
        throw std::runtime_error("File could not be opened");
    }

    std::string line;
    std::string package_name;
    std::string interface_name;
    std::string method_name;

    while (std::getline(ifile, line))
    {
        std::stringstream ss(line);
        std::string first_word;
        ss >> first_word;

        if (!FLexicon::is_fidl_keyword(first_word))
            continue;

        // Package declaration
        if (first_word == "package")
        {
            ss >> package_name;
        }
        // Interface declaration
        else if (first_word == "interface")
        {
            ss >> interface_name;
            model.interfaces.push_back(FInterface(package_name + "." + interface_name));
        }
        // Method declaration
        else if (first_word == "method" || first_word == "broadcast")
        {
            ss >> method_name;
            model.interfaces.back().methods.push_back(FMethod(method_name));
        }
        // In arguments for a method
        else if (first_word == "in")
        {
            std::string m_data;
            // [Constraint] If the fidl file is well-formed, the last pushed model->interface->method is being referenced
            while (std::getline(ifile, m_data))
            {
                // Stop condition == }
                std::size_t found = m_data.find("}");
                if (found != std::string::npos)
                    break;

                std::stringstream method_args(m_data);
                std::string type, name;
                method_args >> type >> name;

                try
                {
                    BaseValue val = FLexicon::create_value(type, name);
                    model.interfaces.back().methods.back().is_parsable = true;
                    model.interfaces.back().methods.back().in_args.push_back(val);
                }
                catch (const std::invalid_argument &e)
                {
                    // There was a non-basic type in the method arguments, mark it non-parsable
                    BaseValue val = BaseValue(type, name);
                    model.interfaces.back().methods.back().is_parsable = false;
                    model.interfaces.back().methods.back().in_args.push_back(val);
                }
            }
        }
        // Out arguments for a method
        else if (first_word == "out")
        {
            std::string m_data;
            // [Constraint] If the fidl file is well-formed, the last pushed model->interface->method is being referenced
            while (std::getline(ifile, m_data))
            {
                // Stop condition == }
                std::size_t found = m_data.find("}");
                if (found != std::string::npos)
                    break;

                std::stringstream method_args(m_data);
                std::string type, name;
                method_args >> type >> name;

                try
                {
                    BaseValue val = FLexicon::create_value(type, name);
                    model.interfaces.back().methods.back().is_parsable = true;
                    model.interfaces.back().methods.back().out_args.push_back(val);
                }
                catch (const std::invalid_argument &e)
                {
                    // There was a non-basic type in the method arguments, mark it non-parsable
                    BaseValue val = FLexicon::create_value(type, name);
                    model.interfaces.back().methods.back().is_parsable = false;
                    model.interfaces.back().methods.back().out_args.push_back(val);
                }
            }
        }
    }
}

void InterfaceParser::_parse_fdepl(std::filesystem::path path, FModel &model)
{
    /*
        Extract the necessary IDs to be able to enforce the firewall rules.
    */
    std::ifstream ifile(path);
    if (!ifile)
    {
        throw std::runtime_error("File could not be opened");
    }

    std::string line;
    std::string tmp_s;

    std::string interface_name;
    uint16_t interface_id;
    std::string method_name;
    uint16_t method_id;

    while (std::getline(ifile, line))
    {
        std::stringstream ss(line);
        std::string first_word;
        ss >> first_word;

        if (!FLexicon::is_fdepl_keyword(first_word))
            continue;

        // Package declaration
        if (first_word == "define")
        {
            ss >> tmp_s; // org.genivi.commonapi.someip.deployment
            ss >> tmp_s; // for
            ss >> tmp_s;
            if (tmp_s != "interface")
                continue;

            ss >> interface_name;
        }
        else if (first_word == "SomeIpServiceID")
        {
            ss >> tmp_s;        // =
            ss >> std::hex >> interface_id >> std::dec; // ServiceID value
            std::cout << interface_id << std::endl;

            for (auto &i : model.interfaces)
            {
                size_t found = interface_name.find(i.get_name());
                if (found != std::string::npos)
                {
                    i.set_service_id(interface_id);
                }
            }
        }
        else if (first_word == "method")
        {
            ss >> method_name;
        }
        else if (first_word == "SomeIpMethodID")
        {
            ss >> tmp_s;     // =
            ss >> method_id; // MethodID value

            for (auto &i : model.interfaces)
            {
                if (interface_name == i.get_name())
                {
                    for (auto &m : i.methods)
                    {
                        if (m.get_name() == method_name)
                            m.set_method_id(method_id);
                    }
                }
            }
        }
    }
}

void InterfaceParser::print()
{
    std::cout << "All found Franca Models: " << std::endl;
    for (auto &m : fmodels)
    {
        m.print();
        m.interfaces.back().methods.back().in_args.back().print();
    }
}
