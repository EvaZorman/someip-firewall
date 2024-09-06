#include "RuleGenerator.hpp"

#include <iostream>
#include <sstream>
#include <fstream>

bool is_value_hex(std::string &s)
{
  return s.compare(0, 2, "0x") == 0
      && s.size() > 2
      && s.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos;
}

std::string read_file(std::filesystem::path path)
{
    // Read in the file at path
    constexpr size_t read_size = std::size_t{4096};
    std::ifstream stream = std::ifstream{path};
    stream.exceptions(std::ios_base::badbit);

    std::string out = std::string{};
    auto buf = std::string(read_size, '\0');
    while (stream.read(&buf[0], read_size))
    {
        out.append(buf, 0, stream.gcount());
    }
    out.append(buf, 0, stream.gcount());
    return out;
}

std::string extract_value(std::string &key_value_str)
{
    size_t delim = key_value_str.find("=") + 1;
    return key_value_str.substr(delim);
}

/*
 * The firewall rule regex form:
 * rule source clientID=<client ID> destination serviceID=<service ID> methodID=<method ID> \\
 * [ log prefix=<prefix> level=<level> ] \\
 * action=<action>
 *
 * There can be an arbitrary amount of space between the entries, so new lines are also
 * possible.
 */
std::vector<std::unique_ptr<Rule>> RuleGenerator::generated_rules;
const boost::regex RuleGenerator::rule_regex = boost::regex("^rule\\s+source\\s+clientID=[A-Za-z0-9]+\\s+destination\\s+serviceID=[A-Za-z0-9]+\\s+methodID=[A-Za-z0-9]+\\s+(?:log\\s+prefix=[A-Za-z0-9]+\\s+level=[A-Za-z]+\\s+)?action=[A-Za-z]+");

const std::unordered_map<std::string, RuleAction> RuleGenerator::action_map{
    {"accept", RuleAction::ACCEPT},
    {"deny", RuleAction::DENY},
    {"log", RuleAction::LOG}};

const std::unordered_map<std::string, LogLevel> RuleGenerator::log_levels{
    {"alert", LogLevel::ALERT},
    {"crit", LogLevel::CRIT},
    {"error", LogLevel::ERROR},
    {"warn", LogLevel::WARN},
    {"info", LogLevel::INFO},
    {"debug", LogLevel::DEBUG}};

RuleAction RuleGenerator::get_action(std::string action)
{
    auto it = action_map.find(action);
    if (it != action_map.end())
    {
        return it->second;
    }
    else
    {
        std::cout << "Unparsable action type: " << action << std::endl;
        return RuleAction::DENY;
    }
}

LogLevel RuleGenerator::get_log_level(std::string level)
{
    auto it = log_levels.find(level);
    if (it != log_levels.end())
    {
        return it->second;
    }
    else
    {
        std::cout << "Unparsable log level type: " << level << std::endl;
        return LogLevel::WARN;
    }
}

RuleGenerator &RuleGenerator::get_instance()
{
    static auto &&rg = RuleGenerator();
    return (rg);
}

void RuleGenerator::_load_rules()
{
    // Loading can be overwritten by using SOMEIP_FIREWALL_RULES env. variable.
    std::filesystem::path path = "./rules/";
    char const *temp = getenv("SOMEIP_FIREWALL_RULES");
    if (temp != NULL)
    {
        path = std::string(temp);
    }

    for (auto const &dir_entry : std::filesystem::directory_iterator{path})
    {
        const std::string file_contents = read_file(dir_entry.path());

        boost::sregex_token_iterator it(file_contents.begin(), file_contents.end(), rule_regex, 0);
        boost::sregex_token_iterator end;

        for (; it != end; ++it)
        {
            _generate_rule(*it);
        }
    }
}

void RuleGenerator::_generate_rule(std::string rule)
{
    /*
        Generates Rule objects and stores them on the heap if no identical Rule is found.

        There is a clear structure to these rules, which is enforced by the regex pattern matching.
        As such, we can be sure there is only two possible structures that need to be parsed.
    */
    std::istringstream istream(rule);
    auto word_count = std::distance(std::istream_iterator<std::string>(istream), std::istream_iterator<std::string>());

    istream.clear();
    istream.seekg(0, std::ios_base::beg);
    if (word_count == 7)
    {
        std::string tmp_s;
        istream >> tmp_s; // rule
        istream >> tmp_s; // source
        istream >> tmp_s; // client_id
        std::string client_str = extract_value(tmp_s);
        istream >> tmp_s; // destination
        istream >> tmp_s; // service_id
        std::string service_str = extract_value(tmp_s);
        istream >> tmp_s; // method_id
        std::string method_str = extract_value(tmp_s);
        istream >> tmp_s; // action
        std::string action = extract_value(tmp_s);

        uint16_t client_id;
        bool client_any = false;
        if (client_str == "any")
        {
            client_id = 0;
            client_any = true;
        }
        else
        {
            if (is_value_hex(client_str))
                client_id = std::stoi(client_str, nullptr, 16);
            else
                client_id = std::stoi(client_str);
        }

        uint16_t service_id;
        bool service_any = false;
        if (service_str == "any")
        {
            service_id = 0;
            service_any = true;
        }
        else
        {
            if (is_value_hex(service_str))
                service_id = std::stoi(service_str, nullptr, 16);
            else
                service_id = std::stoi(service_str);
        }

        uint16_t method_id;
        bool method_any = false;
        if (method_str == "any")
        {
            method_id = 0;
            method_any = true;
        }
        else
        {
            if (is_value_hex(method_str))
                method_id = std::stoi(method_str, nullptr, 16);
            else
                method_id = std::stoi(method_str);
        }

        RuleAction r_action = get_action(extract_value(action));

        Rule r = Rule(client_id, service_id, method_id, r_action);
        if (client_any)
            r.set_clientid_to_any();
        if (service_any)
            r.set_serviceid_to_any();
        if (method_any)
            r.set_methodid_to_any();

        for (auto it = generated_rules.begin(); it != generated_rules.end(); it++)
        {
            if ((**it) == r)
            {
                std::cout << "Identical rule found" << std::endl;
                return;
            }
        }
        generated_rules.push_back(std::make_unique<Rule>(r));
    }
    else if (word_count == 10)
    {
        std::string tmp_s;
        istream >> tmp_s; // rule
        istream >> tmp_s; // source
        istream >> tmp_s; // client_id
        std::string client_str = extract_value(tmp_s);
        istream >> tmp_s; // destination
        istream >> tmp_s; // service_id
        std::string service_str = extract_value(tmp_s);
        istream >> tmp_s; // method_id
        std::string method_str = extract_value(tmp_s);
        istream >> tmp_s; // log
        istream >> tmp_s; // log_prefix
        std::string lprefix = extract_value(tmp_s);
        istream >> tmp_s; // log_level
        std::string llevel = extract_value(tmp_s);
        istream >> tmp_s; // action
        std::string action = extract_value(tmp_s);

        uint16_t client_id;
        bool client_any = false;
        if (client_str == "any")
        {
            client_id = 0;
            client_any = true;
        }
        else
        {
            if (is_value_hex(client_str))
                client_id = std::stoi(client_str, nullptr, 16);
            else
                client_id = std::stoi(client_str);
        }

        uint16_t service_id;
        bool service_any = false;
        if (service_str == "any")
        {
            service_id = 0;
            service_any = true;
        }
        else
        {
            if (is_value_hex(service_str))
                service_id = std::stoi(service_str, nullptr, 16);
            else
                service_id = std::stoi(service_str);
        }

        uint16_t method_id;
        bool method_any = false;
        if (method_str == "any")
        {
            method_id = 0;
            method_any = true;
        }
        else
        {
            if (is_value_hex(method_str))
                method_id = std::stoi(method_str, nullptr, 16);
            else
                method_id = std::stoi(method_str);
        }

        RuleAction r_action = get_action(action);
        LogLevel l_lvl = get_log_level(llevel);

        Rule r = Rule(client_id, service_id, method_id, r_action, lprefix, l_lvl);
        if (client_any)
            r.set_clientid_to_any();
        if (service_any)
            r.set_serviceid_to_any();
        if (method_any)
            r.set_methodid_to_any();

        for (auto it = generated_rules.begin(); it != generated_rules.end(); it++)
        {
            if ((**it) == r)
            {
                std::cout << "Identical rule found" << std::endl;
                return;
            }
        }
        generated_rules.push_back(std::make_unique<Rule>(r));
    }
}

std::string Rule::to_string()
{
    std::stringstream ss;
    ss << "ClientID value: " << client_id;
    ss << " ServiceID value: " << service_id;
    ss << " MethodID value: " << method_id;
    ss << " Action value: " << (int)action;

    return ss.str();
}

bool Rule::clientid_match(uint16_t clientid)
{
    if (client_id_any)
        return true;

    return client_id == clientid;
}

bool Rule::serviceid_match(uint16_t serviceid)
{
    if (service_id_any)
        return true;

    return service_id == serviceid;
}

bool Rule::methodid_match(uint16_t methodid)
{
    if (method_id_any)
        return true;

    return method_id == methodid;
}

RuleAction RuleGenerator::check_against_ruleset(uint16_t &client_id, uint16_t &service_id, uint16_t &method_id)
{
    /*
        If client_id, service_id and method_id all match, return the action corresponding to the rule it matched,
        else deny by default.
    */
    for (auto it = generated_rules.begin(); it != generated_rules.end(); it++)
    {
        Rule r = **it;
        if (r.clientid_match(client_id) && r.serviceid_match(service_id) && r.methodid_match(method_id))
            return r.get_action();
    }

    // Even though there should always be a default deny rule available,
    // default to just denying anything that doesn't match any rule.
    return RuleAction::DENY;
}

void RuleGenerator::print()
{
    std::cout << "--------------------" << std::endl;
    std::cout << "Generated rules: " << std::endl;
    for (auto it = generated_rules.begin(); it != generated_rules.end(); it++)
    {
        Rule r = **it;
        std::cout << "\t" << r.to_string() << std::endl;
    }   
}