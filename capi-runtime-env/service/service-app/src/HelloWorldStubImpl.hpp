#ifndef HELLOWORLDSTUBIMPL_HPP_
#define HELLOWORLDSTUBIMPL_HPP_

#include <CommonAPI/CommonAPI.hpp>
#include <v0/commonapi/examples/HelloWorldStubDefault.hpp>

class HelloWorldStubImpl: public v0_1::commonapi::examples::HelloWorldStubDefault {

public:
    HelloWorldStubImpl();
    virtual ~HelloWorldStubImpl();

    virtual void sayHello(const std::shared_ptr<CommonAPI::ClientId> _client, std::string _name, sayHelloReply_t _return);

};

#endif // E01HELLOWORLDSTUBIMPL_HPP_