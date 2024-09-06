#include "FInterface.hpp"

#include <iostream>

void FModel::print()
{
    std::vector<FInterface>::iterator it;
    std::cout << "-------------------------------" << std::endl;
    std::cout << "Model name: " << model_name << std::endl;
    std::cout << "Interfaces: " << std::endl;
    for (it = interfaces.begin(); it != interfaces.end(); it++)
        it->print();
}

void FInterface::print()
{
    std::vector<FMethod>::iterator it;
    std::cout << "\tInterface name: " << interface_name << std::endl;
    std::cout << "\tInterface/Service ID: " << service_id << std::endl;
    std::cout << "\tMethods: " << std::endl;
    for (it = methods.begin(); it != methods.end(); it++)
        it->print();
}

void FMethod::print()
{
    std::cout << "\t\tMethod name: " << method_name << std::endl;
    std::cout << "\t\tMethod ID: " << method_id << std::endl;
    std::cout << "\t\tIs Parsable: " << is_parsable << std::endl;
    std::cout << "\t\tMethod IN-parameters: " << std::endl;
    for (auto &arg : in_args)
    {
        arg.print();
    }

    std::cout << "\t\tMethod OUT-parameters: " << std::endl;
    for (auto &arg : out_args)
    {
        arg.print();
    }
}

FMethod* FModel::find_method(uint16_t s_id, uint16_t m_id)
{
    for ( auto &i : interfaces )
    {
        if ( i.get_service_id() != s_id )
            continue;
        
        for ( auto &m : i.methods )
        {
            if ( m.get_method_id() == m_id )
                return &m;
        }
    }

    return nullptr;
}
