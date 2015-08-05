/*
* WebSocket Server
*
* http://tylerobrien.com
* https://github.com/TylerOBrien/Cpp-WebSocket-Server
*
* Copyright (c) 2015 Tyler O'Brien
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
* LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
* OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
* WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* */

/*

Add set_onaccept() function. Calls when socket first connects, right afer handshake, but before any data is received.

*/

#ifndef _WEBSOCKET_SERVER_HPP_
#define _WEBSOCKET_SERVER_HPP_

#include "types.hpp"

#include <boost/asio/io_service.hpp>

namespace wss {

enum error {
    ACCEPT=-1, READ=-2, SEND=-3
};

struct EventHandler {
    virtual void open(
        const wss::Socket& client
    ) = 0;

    virtual void close(
        const wss::Socket& client
    ) = 0;

    virtual void reject(
        const wss::Socket& client,
        const std::string& payload
    ) = 0;

    virtual void read(
        const wss::Socket& client,
        const std::string& payload
    ) = 0;

    virtual void error(
        const wss::Socket& client,
        int errtype,
        const boost::system::error_code& errcode
    ) = 0;
};

void start_server(
    const std::string& host,
    uint16_t port
);

void start_server(
    const boost::asio::ip::address& host,
    uint16_t port
);

void start_server(
    const boost::asio::ip::tcp::endpoint& endpoint
);

std::string prepare_payload_for_send(
    const std::string& payload
);

uint64_t send(
    const Socket& client,
    const std::string& payload
);

uint64_t prepare_and_send(
    const Socket& client,
    const std::string& payload
);

boost::asio::io_service& get_io_service();

void set_event_handler(
    EventHandler& handler
);

void set_io_service(
    boost::asio::io_service& ioservice
);

void set_valid_origin(
    const std::string& origin
);

void set_valid_origins(
    const std::vector<std::string>& origins
);

void set_onopen(
    void(*callback)(const Socket&)
);

void set_onclose(
    void(*callback)(const Socket&)
);

void set_onreject(
    void(*callback)(const Socket&,const std::string&)
);

void set_onread(
    void(*callback)(const Socket&,const std::string&)
);

void set_onerror(
    void(*callback)(const Socket&,int,const boost::system::error_code&)
);

}

#endif