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

#ifndef _WEBSOCKET_SERVER_TYPES_HPP_
#define _WEBSOCKET_SERVER_TYPES_HPP_

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/shared_ptr.hpp>

namespace wss {

typedef boost::shared_ptr<boost::asio::streambuf> Buffer;
typedef boost::shared_ptr<boost::asio::ip::tcp::socket> Socket;
typedef boost::shared_ptr<boost::asio::ip::tcp::resolver> Resolver;

typedef boost::asio::ip::tcp::resolver::iterator ResolverIterator;
typedef boost::asio::ip::tcp::resolver::query ResolverQuery;

}

#endif