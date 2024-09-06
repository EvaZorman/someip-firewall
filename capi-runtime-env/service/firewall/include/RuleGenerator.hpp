#ifndef RULE_GENERATOR_HPP
#define RULE_GENERATOR_HPP

#include <boost/regex.hpp>
#include <filesystem>
#include <vector>
#include <unordered_map>
#include <string_view>
#include <string>
#include <memory>

enum class RuleAction
{
    ACCEPT = 0,
    DENY,
    LOG
};

enum class LogLevel
{
    ALERT = 0,
    CRIT,
    ERROR,
    WARN,
    INFO,
    DEBUG
};

class Rule
{
private:
    const uint16_t client_id;
    bool client_id_any = false;
    const uint16_t service_id;
    bool service_id_any = false;
    const uint16_t method_id;
    bool method_id_any = false;
    
    const RuleAction action;

    std::string log_prefix;
    LogLevel log_level;

public:
    Rule() = default;
    ~Rule() = default;
    Rule(uint16_t clientid, uint16_t serviceid, uint16_t methodid, RuleAction raction, std::string lprefix = "", LogLevel llevel = LogLevel::WARN) : 
        client_id(clientid), service_id(serviceid), method_id(methodid), action(raction), log_prefix(lprefix), log_level(llevel) {}

    bool operator==(Rule const& r) const
    {
        return client_id == r.client_id &&
               service_id == r.service_id &&
               method_id == r.service_id &&
               action == r.action;
    }

    std::string to_string();

    bool clientid_match(uint16_t clientid);
    bool serviceid_match(uint16_t serviceid);
    bool methodid_match(uint16_t methodid);

    void set_clientid_to_any() { client_id_any = true; }
    void set_serviceid_to_any() { service_id_any = true; }
    void set_methodid_to_any() { method_id_any = true; }

    RuleAction get_action() const { return action; }
    uint16_t get_clientid() const { return client_id; }
    uint16_t get_serviceid() const { return service_id; }
    uint16_t get_methodid() const { return method_id; }
};

bool is_hex(std::string s);
std::string read_file(std::filesystem::path path);
std::string extract_value(std::string &key_value_str);

class RuleGenerator
{
private:
    static std::vector<std::unique_ptr<Rule>> generated_rules;
    static const boost::regex rule_regex;

    static const std::unordered_map<std::string, RuleAction> action_map;
    static const std::unordered_map<std::string, LogLevel> log_levels;

    RuleGenerator() { _load_rules(); print(); }

    void _load_rules();
    void _generate_rule(std::string rule);

public:
    ~RuleGenerator() = default;
    static RuleGenerator &get_instance();

    static RuleAction get_action(std::string action);
    static LogLevel get_log_level(std::string level);

    RuleAction check_against_ruleset(uint16_t &client_id, uint16_t &service_id, uint16_t &method_id);

    void print();
};

#endif // RULE_GENERATOR_HPP