# WebSocket Server
This API was created with several Boost libraries, most notably Boost ASIO. It is designed for managing network input and output via the WebSocket Protocol RFC6455. The handling of events was kept as an asyncrhonous API as that is what the Boost ASIO library requires and WSS is essentially a lightweight wrapper around Boost ASIO.

# Example
```cpp
#include "WebSocketServer/WebSocketServer.hpp"

#include <iostream>

int main() {
  wss::WebSocketServer server("127.0.0.1", 5000);
  
  for (;;) {
    server.update();
    while (wss::Event event = server.poll()) {
      switch (event.type) {
      case wss::OPEN:
        std::cout << event.socket << " connected" << std::endl;
        break;
      case wss::READ:
        std::cout << event.socket << " sent: " << std::string(event.payload) << std::endl;
        break;
      }
    }
  }
}
```
