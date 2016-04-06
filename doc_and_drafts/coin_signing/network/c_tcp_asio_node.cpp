#include "c_tcp_asio_node.hpp"

#include <functional>

using namespace boost::asio;
using namespace asio_node;

c_tcp_asio_node::c_tcp_asio_node(unsigned int port)
:
	m_asio_threads(),
	m_stop_flag(false),
	m_ioservice(),
	m_recv_queue(),
	m_acceptor(m_ioservice, ip::tcp::endpoint(ip::tcp::v4(), port)),
	m_socket_accept(m_ioservice)
{
	_dbg_mtx("c_tcp_asio_node constructor");
	unsigned int number_of_threads = std::thread::hardware_concurrency();
	if (number_of_threads == 0) number_of_threads = 1;
	auto thread_lambda = [this]() {
		while(!m_stop_flag) {
			m_ioservice.run();
			m_ioservice.reset();
		}
	};
	for(unsigned int i = 0; i < number_of_threads; ++i) {
		m_asio_threads.emplace_back(new std::thread(thread_lambda)); // TODO make_unique
	}

	m_acceptor.async_accept(m_socket_accept, std::bind(&c_tcp_asio_node::accept_handler, this, std::placeholders::_1));
}

c_tcp_asio_node::~c_tcp_asio_node() {
	m_stop_flag = true;
	m_ioservice.stop();
	for (auto &thread_ptr : m_asio_threads) {
		thread_ptr->join();
	}
}

void c_tcp_asio_node::send(c_network_message && message) {
	c_network_message msg(std::move(message));
	ip::address_v4 ip_addr = ip::address_v4::from_string(msg.address_ip); // TODO throw if bad address
	ip::tcp::endpoint endpoint(ip_addr, msg.port); // generate endpoint from message

	std::lock_guard<std::mutex> lg(m_connection_map_mtx);
	auto it = m_connection_map.find(endpoint); // find destination connection
	if (it == m_connection_map.end()) { // not found connection, create new
		m_connection_map.emplace(endpoint, std::make_shared<c_connection>(*this, endpoint));
	}
	assert(!m_connection_map.empty());
	m_connection_map.at(endpoint)->send(std::move(msg.data)); // send raw data
}

c_network_message c_tcp_asio_node::receive() {
	c_network_message message;
	std::lock_guard<std::recursive_mutex> lg(m_recv_queue.get_mutex());
	if (m_recv_queue.empty()) {
		return message;
	}
	message = m_recv_queue.pop();
	return message;
}


void c_tcp_asio_node::accept_handler(const boost::system::error_code &error) {
	if (error) return;
	auto endpoint = m_socket_accept.remote_endpoint();
	std::unique_lock<std::mutex> lg(m_connection_map_mtx);
	m_connection_map.emplace(endpoint, std::make_shared<c_connection>(*this, std::move(m_socket_accept)));
	lg.unlock();
	m_acceptor.async_accept(m_socket_accept, std::bind(&c_tcp_asio_node::accept_handler, this, std::placeholders::_1));
}


/************************************************************/

c_connection::c_connection(c_tcp_asio_node &node, const boost::asio::ip::tcp::endpoint &endpoint)
:
	m_tcp_node(node),
	m_socket(node.m_ioservice),
	m_streambuff(),
	m_ostream(&m_streambuff),
	m_read_size(),
	m_input_buffer()
{
	m_socket.connect(endpoint); // TODO throw if error
}

c_connection::c_connection(c_tcp_asio_node &node, ip::tcp::socket && socket)
:
	m_tcp_node(node),
	m_socket(std::move(socket)),
	m_streambuff(),
	m_ostream(&m_streambuff),
	m_read_size(),
	m_input_buffer()
{
	// start read size
	m_socket.async_read_some(buffer(&m_read_size, sizeof(m_read_size)),
							std::bind(&c_connection::read_size_handler, this, std::placeholders::_1, std::placeholders::_2));
}

void c_connection::send(std::string && message) {
	const uint16_t size_of_message = message.size();
	std::string msg(std::move(message));
	assert(msg.size() == size_of_message);
	std::unique_lock<std::mutex> lg(m_streambuff_mtx);
	m_ostream.write(reinterpret_cast<const char *>(&size_of_message), sizeof(size_of_message));
	m_ostream.write(msg.data(), msg.size());
	lg.unlock();
	m_socket.async_write_some(buffer(m_streambuff.data(), m_streambuff.size()),
							std::bind(&c_connection::write_handler, this, std::placeholders::_1, std::placeholders::_2));
}

void c_connection::write_handler(const boost::system::error_code &error, std::size_t length) {
	if (error) { // error
		return;
	}
	std::lock_guard<std::mutex> lg(m_streambuff_mtx);
	m_streambuff.consume(length); // remove sended data from stream
	if (m_streambuff.size() > 0) {
		m_socket.async_write_some(buffer(m_streambuff.data(), m_streambuff.size()),
							std::bind(&c_connection::write_handler, this, std::placeholders::_1, std::placeholders::_2));
	}
}

void c_connection::read_size_handler(const boost::system::error_code &error, size_t length) {
	if (error) {
		return; // TODO close connection
	}
	m_input_buffer.resize(m_read_size);
	assert(m_read_size > 0); // TODO throw?
	m_socket.async_read_some(buffer(m_input_buffer),
							std::bind(&c_connection::read_data_handler, this, std::placeholders::_1, std::placeholders::_2));
}

void c_connection::read_data_handler(const boost::system::error_code &error, size_t length) {
	if (error) {
		return; // TODO close connection
	}
	// generate c_network_message
	c_network_message network_message;
	auto endpoint = m_socket.remote_endpoint();
	network_message.address_ip = endpoint.address().to_string();
	network_message.port = endpoint.port();
	network_message.data.assign(m_input_buffer.begin(), m_input_buffer.end());
	m_tcp_node.m_recv_queue.push(std::move(network_message));
	m_input_buffer.clear();
}
