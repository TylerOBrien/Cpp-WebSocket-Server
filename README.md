# WebSocket Server
Framework built ontop of [EasySockets](https://github.com/TylerOBrien/EasySockets) that provides a basic event loop for managing connections over the WebSocket protocol.

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
