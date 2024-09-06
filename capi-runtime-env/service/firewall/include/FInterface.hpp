#ifndef FINTERFACE_HPP
#define FINTERFACE_HPP

#include <iostream>
#include <string>
#include <vector>
#include <memory>

#include <boost/archive/binary_iarchive.hpp>

class BaseValue
{
protected:
    std::string type;
    std::string val_name;

public:
    BaseValue() = default;
    virtual ~BaseValue() = default;

    BaseValue(std::string type, std::string name) : type(type), val_name(name) {}
    std::string get_name() const { return val_name; }
    std::string get_type() const { return type; }
    
    virtual void print()
    {
        std::cout << "\t\t\t- Name: " << val_name << std::endl;
        std::cout << "\t\t\t- Type: " << type << std::endl;
    }
};

class FMethod
{
private:
    std::string method_name;
    uint16_t method_id;

public:
    bool is_parsable;

    // unique_ptr is not always the best choice for polymorphism
    // due to slicing or memory leaks when assigned a derived class object
    // to a base class unique_ptr.
    std::vector<BaseValue> in_args;
    std::vector<BaseValue> out_args;

    FMethod(std::string name) : method_name(name) { method_id = 0; };

    std::string get_name() const { return method_name; }
    uint16_t get_method_id() { return method_id; }
    void set_method_id(u_int16_t m_id) { method_id = m_id; }

    void print();
};

class FInterface
{
private:
    std::string interface_name;
    uint16_t service_id;

public:
    std::vector<FMethod> methods;

    FInterface(std::string name) : interface_name(name) { service_id = 0; };

    std::string get_name() const { return interface_name; }
    uint16_t get_service_id() const { return service_id; }
    void set_service_id(u_int16_t s_id) { service_id = s_id; }
    void print();
};

class FModel
{
private:
    std::string model_name;

public:
    std::vector<FInterface> interfaces;

    FModel(std::string name) : model_name(name) {}

    FMethod* find_method(uint16_t s_id, uint16_t m_id);
    std::string get_name() const { return model_name; }
    void print();
};

// class FTypeCollection
// {
// private:
//     std::string tc_name;

// public:
//     std::vector<std::shared_ptr<BaseValue>> ftypes;

//     FTypeCollection(std::string name) : tc_name(name) {}

//     std::string get_name();
// };

// class FInterface
// {
// private:
//     std::string i_name;

// public:
//     std::vector<std::shared_ptr<FMethod>> methods;
//     std::vector<std::shared_ptr<FMethod>> broadcasts;

//     FInterface(std::string name) : i_name(name){};

//     std::string get_name();
// };

#endif // FINTERFACE_HPP