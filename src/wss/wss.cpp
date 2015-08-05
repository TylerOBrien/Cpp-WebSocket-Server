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

#include "wss.hpp"
#include "utility.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/write.hpp>
#include <boost/bind/bind.hpp>
#include <boost/format.hpp>
#include <boost/uuid/sha1.hpp>

using boost::archive::iterators::base64_from_binary;
using boost::archive::iterators::transform_width;

namespace wss {

typedef base64_from_binary<transform_width<const char*,6,8>> base64_encode_t;

/* * * * * * * * * * * * * * * * * * *
 * * Identifiers
 * * * * * * * * * * * * * * * * * * */

enum event {
    CONNECT_REQUEST=1, CONNECT_ACCEPTED, FRAME_HEAD, FRAME_126, FRAME_127, PAYLOAD
};

enum nbytes {
    FRAME=2, MASK=4, PAYLOAD_LENGTH=7, PAYLOAD_LENGTH_EXT_126=2, PAYLOAD_LENGTH_EXT_127=8
};

enum opcode {
    CONTINUATION=0, TEXT=1, BINARY=2, CLOSE=8, PING=9, PONG=10
};

/* * * * * * * * * * * * * * * * * * *
 * * Empty Functions
 * * * * * * * * * * * * * * * * * * */

/*
 * These empty functions are necessary to allow the user of WSS to not need to assign all four
 * functions. Without them the variables wouldn't be defined so the API would produce runtime
 * errors if a function hasn't been set by the user and is called by WSS's internal functions.
 * */

void empty_onopen(const Socket&) {}
void empty_onclose(const Socket&) {}
void empty_onreject(const Socket&,const std::string&) {}
void empty_onread(const Socket&,const std::string&) {}
void empty_onerror(const Socket&,int,const boost::system::error_code&) {}

/* * * * * * * * * * * * * * * * * * *
 * * Global Variables
 * * * * * * * * * * * * * * * * * * */

const char* WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const char* WEBSOCKET_CONNECT_RESPONSE = "\
HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: %s\r\n\r\n";

uint64_t uniqueid = 0;
EventHandler* event_handler = NULL;

boost::asio::io_service* ioservice = NULL;
boost::asio::ip::tcp::acceptor* acceptor = NULL;

std::map<uint64_t,uint8_t> events;
std::vector<std::string> valid_origins;

void(*fn_onopen)(const Socket&) = empty_onopen;
void(*fn_onclose)(const Socket&) = empty_onclose;
void(*fn_onreject)(const Socket&,const std::string&) = empty_onreject;
void(*fn_onread)(const Socket&,const std::string&) = empty_onread;
void(*fn_onerror)(const Socket&,int,const boost::system::error_code&) = empty_onerror;

/* * * * * * * * * * * * * * * * * * *
 * * Utilities
 * * * * * * * * * * * * * * * * * * */

namespace util {

struct HTTPRequest {
	std::string method;
	std::string uri;
	std::string version;
	std::string request;
	std::map<std::string,std::string> args;
};

/*
 * split_string() returns nothing
 *
 * Input:
	* dest			Destination of the split values.
	* src			Source string to be split.
	* delim			Delimeter to split the source by.
 * 
 * Splits a string by the passed delimeter. Is only used by the
 * function "parse_http_request" to split apart the HTTP arguments.
 *
 * If the delimeter is not found then the destination vector will
 * contain only a single element, equal to the source string.
 * */
void split_string(
    std::vector<std::string>& destination,
    const std::string& source,
    const std::string& delim)
{
	if (source.size() < delim.size()) {
		destination.push_back(source);
	} else {
		std::string buffer;
		const char* itr = source.c_str();

		while (*itr) {
			if (memcmp(itr, delim.c_str(), delim.size()) == 0) {
				destination.push_back(buffer);
				buffer.clear();
				std::size_t temp = delim.size();
				while (temp-- && *itr++); /* Move itr past current match. */
			} else {
				buffer += *itr++;
			}
		}

		destination.push_back(buffer);
	}
}

/*
 * parse_http_request() returns nothing
 *
 * Input:
	* request		HTTP request to be parsed.
	* dest			Destination of the information parsed from the request.
 *
 * Parses the passed HTTP request, which is assumed to be properly formatted. Arguments
 * are stored in an std::map<std::string,std::string> object.
 * */
void parse_http_request(
    const std::string& request,
    HTTPRequest* dest)
{
	std::vector<std::string> lines;
	std::vector<std::string> buffer;

	split_string(lines, request, "\r\n");
	split_string(buffer, lines[0], " ");

	dest->method = buffer[0];
	dest->uri = buffer[1];
	dest->version = buffer[2];
	dest->args.clear();

	for (std::vector<std::string>::iterator itr = lines.begin()+1; itr != lines.end(); itr++) {
		buffer.clear();
		split_string(buffer, *itr, ": ");
		if (buffer.size() == 2) {
			dest->args.insert(std::make_pair(buffer[0],buffer[1]));
		}
	}
}

/*
 * http_request_arg() returns std::string
 *
 * Input:
	* request_raw	Un-parsed copy of HTTP request.
	* arg			The argument to be returned.
 *
 * Parses the passed HTTP request and returns the value of the argument
 * equal to the passed 'arg' value. Returns an empty string if the value
 * is not found.
 * */
std::string http_request_arg(
    const std::string& request_raw,
    const std::string& arg)
{
	HTTPRequest request;
	parse_http_request(request_raw, &request);

	std::map<std::string,std::string>::iterator itr = request.args.find(arg);

	if (itr != request.args.end()) {
		return itr->second;
	} else {
		return "";
	}
}

/*
 * base64_encode() returns std::size_t
 * * * *
 * * * * This function was not written by me.
 * * * * - Tyler O'Brien
 * * * *
 * Credit: http://stackoverflow.com/a/12784770
 * Archive: https://archive.is/pZY0y#12784770
 * * * *
 * */
std::size_t base64_encode(
    char* dest,
    const char* src,
    std::size_t nbytes)
{
	char tail[3] = {0};

	std::size_t one_third_len = nbytes/3;
	std::size_t len_rounded_down = one_third_len*3;
	std::size_t j = len_rounded_down + one_third_len;

	std::copy(base64_encode_t(src), base64_encode_t(src+len_rounded_down), dest);

	if (len_rounded_down != nbytes) {
		std::size_t i = 0;
		for(; i < nbytes - len_rounded_down; i++) {
			tail[i] = src[len_rounded_down+i];
		}
		std::copy(base64_encode_t(tail), base64_encode_t(tail+3), dest+j);
		for(i = nbytes+one_third_len+1; i < j+4; i++) {
			dest[i] = '=';
		}
		return i;
	}

	return j;
}

/*
 * sha1_hash() returns nothing
 * * * *
 * * * * This function was not written by me.
 * * * * - Tyler O'Brien
 * * * *
 * Credit: https://gist.github.com/jhasse/990731
 * Archive: https://archive.is/Jp1eS
 * * * *
 * */
void sha1_hash(
    char* dest,
    const char* src,
    std::size_t nbytes)
{
	boost::uuids::detail::sha1 sha1;
	unsigned int digest[5];

	sha1.process_bytes(src, nbytes);
	sha1.get_digest(digest);

	for(int8_t i = 0; i < 5; i++) {
		const char* tmp = reinterpret_cast<char*>(digest);
		dest[i*4] = tmp[i*4+3];
		dest[i*4+1] = tmp[i*4+2];
		dest[i*4+2] = tmp[i*4+1];
		dest[i*4+3] = tmp[i*4];
	}
}

/*
 * encode_websocket_key() returns std::string
 *
 * Input:
	* key			WebSocket key to be encoded.
 *
 * Encodes the key given by the Sec-WebSocket-Key HTTP request argument.
 * */
std::string encode_websocket_key(
    std::string key)
{
	key += WEBSOCKET_GUID;

	char hash[20] = {0};
	char base64[128] = {0};

	sha1_hash(hash, key.c_str(), key.size());
	base64_encode(base64, hash, 20);

	return base64;
}

/*
 * unmask_payload() returns std::string
 *
 * Input:
	* payload		Masked payload data.
	* mask			Mask data that masks the payload.
	* nbytes		Length of the payload in bytes.
 *
 * Unmasks and returns the payload.
 * */
std::string unmask_payload(
    const int8_t* payload,
    const uint8_t* mask,
    std::size_t nbytes)
{
	std::string unmasked;

	unmasked.reserve(nbytes);

	for (std::size_t i = 0; i < nbytes; i++) {
		unmasked.push_back(payload[i] ^ mask[i%4]);
	}

	return unmasked;
}

/*
 * make_websocket_connect_response() returns std::string
 *
 * Input:
	* request_raw	Un-parsed HTTP request.
 *
 * Generates the connect response which is to be sent to any client
 * that is requesting a connection.
 * */
std::string websocket_connect_response(
    const std::string& request_raw)
{
	HTTPRequest request;
	parse_http_request(request_raw, &request);

	std::string encoded_key = encode_websocket_key(request.args["Sec-WebSocket-Key"]);

	return boost::str(boost::format(WEBSOCKET_CONNECT_RESPONSE) % encoded_key);
}

}

/* * * * * * * * * * * * * * * * * * *
 * * Function Declarations
 * * * * * * * * * * * * * * * * * * */

void accept();

uint64_t read(
    const Socket& socket,
    std::size_t nbytes
);

uint64_t read_until(
    const Socket& socket,
    const std::string& terminator
);

uint64_t send_connect_response(
    const Socket& socket,
    const std::string& data
);

/* * * * * * * * * * * * * * * * * * *
 * * Server Operations
 * * * * * * * * * * * * * * * * * * */

/*
 * start_server()
 * */
void start_server(
    const std::string& host,
    uint16_t port)
{
    start_server(
        boost::asio::ip::address::from_string(host),
        port
    );
}

/*
 * start_server()
 * */
void start_server(
    const boost::asio::ip::address& host,
    uint16_t port)
{
    start_server(
        boost::asio::ip::tcp::endpoint(host, port)
    );
}

/*
 * start_server()
 * */
void start_server(
    const boost::asio::ip::tcp::endpoint& endpoint)
{
    acceptor = new boost::asio::ip::tcp::acceptor(*ioservice, endpoint);
    accept();
    ioservice->run();
    delete acceptor;
}

/*
 * prepare_payload_for_send() returns std::string
 *
 * Input:
	* payload		Payload data to be prepared.
 *
 * Formats the passed payload data to be sent to a client, as per
 * the WebSocket protocol. The protocol merely requires the length
 * of the payload to be prepended to the payload data.
 *
 * The length of the payload data determines the number of bytes
 * that are used to store the length before the data, which is
 * either one byte, two bytes or eight bytes.
 * */
std::string prepare_payload_for_send(
    const std::string& payload)
{
	std::string result;

	result += -127;

	if (payload.size() < 126) {
		result += char(payload.size());
	} else if (payload.size() < 65536) {
		result += 126;
		result += char((payload.size()>>8)&255);
		result += char(payload.size()&255);
	} else {
		result += 127;
		result += char(((uint64_t)payload.size()>>56)&255);
		result += char(((uint64_t)payload.size()>>48)&255);
		result += char(((uint64_t)payload.size()>>40)&255);
		result += char(((uint64_t)payload.size()>>32)&255);
		result += char((payload.size()>>24)&255);
		result += char((payload.size()>>16)&255);
		result += char((payload.size()>>8)&255);
		result += char(payload.size()&255);
	}

	result += payload;

	return result;
}

/* * * * * * * * * * * * * * * * * * *
 * * Event Handlers
 * * * * * * * * * * * * * * * * * * */

/*
 * handle_accept()
 * */
void handle_accept(
    const Socket& socket,
    const boost::system::error_code& error)
{
	if (!error) {
		uint64_t eventid = read_until(socket, "\r\n\r\n");
		events.insert(std::make_pair(eventid,event::CONNECT_REQUEST));
	} else {
        if (event_handler != NULL) {
            return event_handler->error(socket, error::ACCEPT, error);
        } else {
            return fn_onerror(socket, error::ACCEPT, error);
        }
	}

	accept();
}

/*
 * handle_connect_request() returns nothing
 *
 * Input:
	* socket		Client that is requesting connection.
	* data			Raw HTTP request containg request information.
 *
 * Determines if the incoming connection request should be accepted. If the
 * origin found in the HTTP request matches one of the valid origins, or there
 * aren't any valid origins defined (i.e. all origins allowed) then the
 * connection will be accepted.
 *
 * Assumes that the incoming HTTP request (i.e. the data variable) is
 * properly formatted.
 * */
void handle_connect_request(
    const Socket& socket,
    const std::string& data)
{
	if (valid_origins.empty() == false) {
		std::string origin = util::http_request_arg(data, "Origin");
		if (std::find(valid_origins.begin(),valid_origins.end(),origin) == valid_origins.end()) {
            if (event_handler != NULL) {
                return event_handler->reject(socket, origin);
            } else {
                return fn_onreject(socket, origin);
            }
		}
	}

	std::string response = util::websocket_connect_response(data);
	uint64_t eventid = send_connect_response(socket,response);

	events.insert(std::make_pair(eventid,event::CONNECT_ACCEPTED));
}

/*
 * handle_frame_head() returns nothing
 *
 * Input:
	* socket		Client which sent the message frame.
	* data			Contents of the frame header.
 *
 * Processes the header of the WebSocket message frame, and determines
 * if the message is a connection close event (i.e. the opcode is
 * equal to 8), or if the message is a payload. 
 *
 * Consult WebSocket Protocol RFC6455 Section 5.2 for more information.
 * */
void handle_frame_head(
    const Socket& socket,
    const std::string& data)
{
	uint16_t head = *(uint16_t*)(data.c_str());
	uint8_t opcode = (*(uint8_t*)&head)&15;

	if (opcode == opcode::CLOSE) {
        if (event_handler != NULL) {
            return event_handler->close(socket);
        } else {
            return fn_onclose(socket);
        }
	}

	uint8_t payload_length = *(data.c_str()+1)&127;
	uint64_t eventid;
	uint8_t event_type;

	switch (payload_length) {
	case 126: 
		eventid = wss::read(socket, nbytes::PAYLOAD_LENGTH_EXT_126);
		event_type = event::FRAME_126;
		break;
	case 127: 
		eventid = wss::read(socket, nbytes::PAYLOAD_LENGTH_EXT_127);
		event_type = event::FRAME_127;
		break;
	default: 
		eventid = wss::read(socket, nbytes::MASK+payload_length);
		event_type = event::PAYLOAD;
		break;
	}

	events.insert(std::make_pair(eventid,event_type)); 
}

/*
 * handle_frame_126() returns nothing
 *
 * Input:
	* socket		Client which sent the message frame.
	* data			Masked payload data.
 *
 * Processes payload data from a message frame which had a
 * payload length of 126, meaning that the true payload length
 * is contained in the two bytes which follow.
 *
 * Consult WebSocket Protocol RFC6455 Section 5.2 for more information.
 * */
void handle_frame_126(
    const Socket& socket,
    const std::string& data)
{
	uint8_t* bytes = (uint8_t*)data.c_str();
	uint16_t payload_length = (bytes[0]<<8) + bytes[1];
	uint64_t eventid = wss::read(socket, nbytes::MASK+payload_length);
	
	events.insert(std::make_pair(eventid,wss::event::PAYLOAD));
}

/*
 * handle_frame_127() returns nothing
 *
 * Input:
	* socket		Client which sent the message frame.
	* data			Masked payload data.
*
* Processes payload data from a message frame which had a
* payload length of 127, meaning that the true payload length
* is contained in the eight bytes which follow.
*
* Consult WebSocket Protocol RFC6455 Section 5.2 for more information.
 * */
void handle_frame_127(
    const Socket& socket,
    const std::string& data)
{
	uint8_t* bytes = (uint8_t*)data.c_str();
	uint64_t payload_length = 
		((uint64_t)bytes[0]<<56) + ((uint64_t)bytes[1]<<48) + 
		((uint64_t)bytes[2]<<40) + ((uint64_t)bytes[3]<<32) + 
		(bytes[4]<<24) + (bytes[5]<<16) + (bytes[6]<<8) + bytes[7];

	uint64_t eventid = wss::read(socket, nbytes::MASK+payload_length);
	
	wss::events.insert(std::make_pair(eventid,wss::event::PAYLOAD));
}

/*
 * handle_payload() returns nothing
 *
 * Input:
	* socket		Client which sent the payload.
	* data			Masked payload data.
 * 
 * Unmasks the passed payload data and passed it to the 'onread' handler.
 * */
void handle_payload(
    const Socket& socket,
    const std::string& data)
{
	const int8_t* payload = (const int8_t*)data.c_str()+nbytes::MASK;
	const uint8_t* mask = (const uint8_t*)data.c_str();

	std::string unmasked_payload = util::unmask_payload(payload, mask, data.size()-nbytes::MASK);

    if (event_handler != NULL) {
        event_handler->read(socket, unmasked_payload);
    } else {
        fn_onread(socket, unmasked_payload);
    }

	uint64_t eventid = wss::read(socket, nbytes::FRAME);

	events.insert(std::make_pair(eventid,event::FRAME_HEAD));
}

/*
 * handle_accept() returns nothing
 *
 * Input:
	* socket		Client to receive data from.
	* buffer		The asio::streambuf container of the sent data.
	* eventid		Identifier of the event.
	* error			Storage of any potential error.
 *
 * Processes all data that is received from a client. Is a
 * catch-all function for the five different types of read
 * events, namely reading the head of the message frame, the
 * payload data, the extended lengths of payload data, and
 * a websocket connect request.
 *
 * Consult WebSocket Protocol RFC6455 Section 5.2 for more information.
 * */
void handle_read(
    const Socket& socket,
    const Buffer& buffer,
    uint64_t eventid,
    const boost::system::error_code& error)
{
	if (!error) {
		std::string data_received;
        util::buffer_to_string(data_received, buffer);

		std::map<uint64_t,uint8_t>::iterator itr = events.find(eventid);
		uint8_t event_type = itr->second;

		events.erase(itr);

		switch (event_type) {
		case event::FRAME_HEAD: handle_frame_head(socket,data_received); break;
		case event::PAYLOAD: handle_payload(socket,data_received); break;
		case event::FRAME_126: handle_frame_126(socket,data_received); break;
		case event::FRAME_127: handle_frame_127(socket,data_received); break;
		case event::CONNECT_REQUEST: handle_connect_request(socket,data_received); break;
		}
	} else {
        if (event_handler != NULL) {
            event_handler->error(socket, error::READ, error);
        } else {
            fn_onerror(socket, error::READ, error);
        }
	}
}

/*
 * handle_send_connect_response() returns nothing
 *
 * Input:
	* socket		Client to which the response was sent.
	* eventid		Identifier of the event.
	* error			Storage of any protential error.
 *
 * This function exists because it requires an event to be stored
 * in the event map, whereas the regular send function does not. If the
 * regular send handler were to be used, it would need to check for
 * the existance of the eventid every time, even though it only
 * exists once, when a client receives the connection response.
 * */
void handle_send_connect_response(
    const Socket& socket,
    uint64_t eventid,
    const boost::system::error_code& error)
{
	if (!error) {
        if (event_handler != NULL) {
            event_handler->open(socket);
        } else {
            fn_onopen(socket);
        }
		events.erase(events.find(eventid));
		events.insert(std::make_pair(wss::read(socket,nbytes::FRAME), event::FRAME_HEAD));
	} else {
        if (event_handler != NULL) {
            event_handler->error(socket, error::SEND, error);
        } else {
            fn_onerror(socket, error::SEND, error);
        }
	}
}

/*
 * handle_send() returns nothing
 *
 * Input:
	* socket		Client to which the payload was sent.
	* eventid		Identifier of the event.
	* error			Storage of potential error.
 *
 * As there are no externally facing handlers for sending payloads
 * to clients, this function only determines if there was an error.
 * */
void handle_send(
    const Socket& socket,
    uint64_t eventid,
    const boost::system::error_code& error)
{
	if (error) {
        if (event_handler != NULL) {
            event_handler->error(socket, error::SEND, error);
        } else {
            fn_onerror(socket, error::SEND, error);
        }
	}
}

/* * * * * * * * * * * * * * * * * * *
 * * Server
 * * * * * * * * * * * * * * * * * * */

/*
 * accept() returns nothing
 *
 * Listens for incoming socket connections. Upon receiving a
 * connection, the handle_accept() function is called.
 * */
void accept()
{
	Socket socket = util::create_socket();

	acceptor->async_accept(*socket,
		boost::bind(&handle_accept, socket, boost::asio::placeholders::error)
	);
}

/*
 * read() returns uint64_t
 *
 * Input:
	* socket		Client which is being read from.
	* nbytes		Number of bytes to read.
 *
 * Waits for any incoming data from the passed client that is equal
 * to 'nbytes' in length. Will do nothing until exactly that number
 * of bytes is received (any additional bytes will not be passed
 * and will only be received upon another read call).
 * */
uint64_t read(
    const Socket& socket,
    std::size_t nbytes)
{
	Buffer buffer = util::create_buffer(nbytes);

	boost::asio::async_read(*socket, *buffer, 
		boost::bind(&handle_read, socket, buffer, uniqueid, boost::asio::placeholders::error)
	);

	return uniqueid++;
}

/*
 * read_until() returns uint64_t
 *
 * Input:
	* socket		Client which is being read from.
	* terminator	Value to read up to.
 *
 * Waits for any incoming data up until receiving data that
 * is equal to the passed terminator value.
 *
 * For example: to read an HTTP request, a terminator
 * of "\r\n\r\n" would be given as all valid HTTP requests
 * end with that value.
 * */
uint64_t read_until(
    const Socket& socket,
    const std::string& terminator)
{
	Buffer buffer = util::create_buffer();

	boost::asio::async_read_until(*socket, *buffer, terminator.c_str(),
		boost::bind(&handle_read, socket, buffer, uniqueid, boost::asio::placeholders::error)
	);

	return uniqueid++;
}

/*
 * send() returns uint64_t
 *
 * Input:
	* socket		Client to send data to.
	* data			Payload to be sent.
 *
 * Sends the passed payload to the client.
 * */
uint64_t send(
    const Socket& socket,
    const std::string& data)
{
	boost::asio::async_write(
        *socket,
        boost::asio::buffer(data.c_str(),data.size()),
		boost::bind(&handle_send, socket, uniqueid, boost::asio::placeholders::error)
	);

	return uniqueid++;
}

/*
 * prepare_and_send() returns uint64_t
 *
 * Input:
	* socket		Client to send data to.
	* data			Payload to be sent.
 *
 * */
uint64_t prepare_and_send(
    const Socket& socket,
    const std::string& data)
{
    return send(socket, prepare_payload_for_send(data));
}

/*
 * send_connect_response() returns uint64_t
 *
 * Input:
	* socket		Client to send data to.
	* data			Connect response to be sent.
 *
 * Sends the passed connect response payload to the client. This function
 * exists merely because the handling of a sent connection response
 * is slightly more computationally expensive than a regular send operation
 * and it only needs to be done once per connection, so this has its own
 * function for the sake of performance.
 * */
uint64_t send_connect_response(
    const Socket& socket,
    const std::string& data)
{
	boost::asio::async_write(
        *socket,
        boost::asio::buffer(data.c_str(),data.size()),
		boost::bind(
            &handle_send_connect_response, socket, uniqueid, boost::asio::placeholders::error
        )
	);

	return uniqueid++;
}

/* * * * * * * * * * * * * * * * * * *
 * * Getters/Setters
 * * * * * * * * * * * * * * * * * * */

/*
 * get_io_service()
 * */
boost::asio::io_service& get_io_service()
{
    return *ioservice;
}

/*
 * set_event_handler()
 * */
void set_event_handler(
    EventHandler& handler)
{
    event_handler = &handler;
}

/*
 * set_io_service()
 * */
void set_io_service(
    boost::asio::io_service& value)
{
	ioservice = &value;
}

/*
 * set_valid_origin()
 * */
void set_valid_origin(
    const std::string& origin)
{
    valid_origins.clear();
    valid_origins.push_back(origin);
}

/*
 * set_valid_origins()
 * */
void set_valid_origins(
    const std::vector<std::string>& origins)
{
	valid_origins.assign(origins.begin(), origins.end());
}

/*
 * set_onopen()
 * */
void set_onopen(
    void(*callback)(const Socket&))
{
	fn_onopen = callback;
}

/*
 * fn_onclose()
 * */
void set_onclose(
    void(*callback)(const Socket&))
{
	fn_onclose = callback;
}

/*
 * set_onreject()
 * */
void set_onreject(
    void(*callback)(const Socket&,const std::string&))
{
	fn_onreject = callback;
}

/*
 * set_onread()
 * */
void set_onread(
    void(*callback)(const Socket&,const std::string&))
{
	fn_onread = callback;
}

/*
 * set_onerror()
 * */
void set_onerror(
    void(*callback)(const Socket&,int,const boost::system::error_code&))
{
	fn_onerror = callback;
}

}