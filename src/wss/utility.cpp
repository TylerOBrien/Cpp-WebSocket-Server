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

#include "utility.hpp"
#include "wss.hpp"

#include <boost/asio/buffers_iterator.hpp>

namespace wss {
namespace util {

/*
 * buffer_to_string()
 * */
void buffer_to_string(
    std::string& dest,
    const wss::Buffer& src)
{
    boost::asio::streambuf::const_buffers_type data = src->data();

	dest = std::string(
        boost::asio::buffers_begin(data),
        boost::asio::buffers_begin(data) + src->size()
    );
}

/*
 * create_resolver()
 * */
wss::Resolver create_resolver()
{
    return wss::Resolver(new wss::Resolver::element_type(get_io_service()));
}

/*
 * create_socket()
 * */
wss::Socket create_socket()
{
    return wss::Socket(new wss::Socket::element_type(get_io_service()));
}

/*
 * create_buffer()
 * */
wss::Buffer create_buffer()
{
    return wss::Buffer(new wss::Buffer::element_type);
}

/*
 * create_buffer()
 * */
wss::Buffer create_buffer(
    std::size_t nbytes)
{
    return wss::Buffer(new wss::Buffer::element_type(nbytes));
}

}
}