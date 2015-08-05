WebSocket Server
----------
This API was created with several Boost libraries, most notably Boost ASIO. It is designed for managing network input and output via the WebSocket Protocol RFC6455. The handling of events was kept as an asyncrhonous API as that is what the Boost ASIO library requires and WSS is essentially a lightweight wrapper around Boost ASIO.

Example
----------
```cpp
#include "wss/wss.hpp"
#include <iostream>

class Handler : public wss::EventHandler {
private:
    std::list<wss::Socket> __clients;
public:
    void open(const wss::Socket& client) {
        __clients.push_back(client);

        std::cout << client << " connected" << std::endl;
        std::cout << "Number of clients: " << __clients.size() << std::endl;
    }

    void close(const wss::Socket& client) {
        __clients.remove(client);

        std::cout << client << " dropped" << std::endl;
        std::cout << "Number of clients: " << __clients.size() << std::endl;
    }

    void read(const wss::Socket& client, const std::string& data) {
        std::cout << client << " sent: " << data << std::endl;
    }

    void reject(const wss::Socket&, const std::string&) {}
    void error(const wss::Socket&, int, const boost::system::error_code&) {}
};

int main() {
    Handler handler;
    boost::asio::io_service ioservice;

    wss::set_event_handler(handler);
    wss::set_io_service(ioservice);

    wss::start_server("127.0.0.1", 5000);
}
```
