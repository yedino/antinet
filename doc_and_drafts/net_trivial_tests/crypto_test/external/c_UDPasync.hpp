#ifndef C_UDPASYNC_HPP
#define C_UDPASYNC_HPP

#include "c_statistics.hpp"
#include "c_locked_queue.hpp"
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include "log.hpp"
#include <array>
#include <thread>


using boost::asio::ip::udp;

class c_UDPasync {
public:
		static const int network_buffer_size = 4096;

		c_UDPasync (const std::string &host, unsigned short server_port, unsigned short local_port = 0);

		~c_UDPasync ();

		void send (const std::string &message);

		inline bool has_messages () {
			return !incomingMessages.empty();
		};

		std::string pop_message ();

private:
		// Network send/receive stuff
		boost::asio::io_service io_service;
		udp::socket socket;
		udp::endpoint server_endpoint;
		udp::endpoint remote_endpoint;
		std::array<char, network_buffer_size> recv_buffer;
		std::thread service_thread;

		// Queues for messages
		c_locked_queue<std::string> incomingMessages;

		void start_receive ();

		void handle_receive (const boost::system::error_code &error, std::size_t bytes_transferred);

		void run_service ();

		c_UDPasync (c_UDPasync &) = delete;

		// c_statistics
		c_statistics statistics;
};

#endif // C_UDPASYNC_HPP
