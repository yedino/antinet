#include <iostream>
#include <chrono>
#include <thread>
#include <fstream>
#include <memory>
#include <fstream>
#include <signal.h>
#include <future>
#include "external/ecdh_ChaCha20_Poly1305.hpp"
#include "external/c_UDPasync.hpp"

std::fstream logger("./log", std::ios_base::trunc | std::ios_base::in | std::ios_base::out);
std::atomic<bool> end;

void start_recieving (c_UDPasync &connection,
				const ecdh_ChaCha20_Poly1305::sharedkey_t &shared_key,
				const ecdh_ChaCha20_Poly1305::nonce_t &nonce) {

	while (!end) {
		if (connection.has_messages()) {
			std::string msg = connection.pop_message();
			std::string decrypted = ecdh_ChaCha20_Poly1305::decrypt(msg, shared_key, nonce);

			logger << "--------- NEW MESSAGE:\n";
			logger << "encrypted: ";
			for (char c : msg) {
				logger << int(c) << ' ';
			}
			logger << "\ndecrypted: ";
			for (char c : decrypted) {
				logger << int(c) << ' ';
			}
			logger << "  -->   " << decrypted << "\n\n";

			std::cout << decrypted << endl << "#> ";
			std::cout.flush();
		}

		std::this_thread::yield();
	}
}

void handle_sending (c_UDPasync &connection,
				const ecdh_ChaCha20_Poly1305::sharedkey_t &shared_key,
				const ecdh_ChaCha20_Poly1305::nonce_t &nonce) {

	std::string msg;

	while (!end) {
		std::cout << "#> ";
		std::getline(std::cin, msg);
		std::string encrypted = ecdh_ChaCha20_Poly1305::encrypt(msg, shared_key, nonce);

		logger << "--------- MESSAGE SENT:\n";
		logger << "encrypted: ";
		for (char c : encrypted) {
			logger << int(c) << ' ';
		}
		logger << "\ndecrypted: ";
		for (char c : msg) {
			logger << int(c) << ' ';
		}
		logger << "  -->   " << msg << "\n\n";

		connection.send(encrypted);
		std::this_thread::yield();
	}
}


void generate_config (const std::string &filename) {
	std::fstream config(filename, std::ios_base::trunc | std::ios_base::in | std::ios_base::out);
	if (!config.good()) {
		throw std::runtime_error("error while opening a file: " + filename);
	}

	auto keypair = ecdh_ChaCha20_Poly1305::generate_keypair();
	config << ecdh_ChaCha20_Poly1305::serialize(keypair.pubkey.data(), keypair.pubkey.size());
	config << '\n';
	config << ecdh_ChaCha20_Poly1305::serialize(keypair.privkey.data(), keypair.privkey.size());
}

ecdh_ChaCha20_Poly1305::keypair_t load_keypair (const std::string &filename) {
	std::ifstream config(filename, std::ios_base::out);
	if (!config.good()) {
		throw std::runtime_error("error while opening a file: " + filename);
	}

	ecdh_ChaCha20_Poly1305::keypair_t result;
	std::string input;

	std::getline(config, input);
	result.pubkey = ecdh_ChaCha20_Poly1305::deserialize_pubkey(input);

	std::getline(config, input);
	result.privkey = ecdh_ChaCha20_Poly1305::deserialize_privkey(input);
	config.close();
	return result;
}

//ecdh_ChaCha20_Poly1305::nonce_t do_handshake (const std::string &ipv6_addr,
//				const ecdh_ChaCha20_Poly1305::pubkey_t &pubkey,
//				c_UDPasync &connection) {
//
//	std::cout << "handshake started...\n";
//	logger << "handshake started...\n";
//	auto handshake_keypair = ecdh_ChaCha20_Poly1305::generate_keypair();
//	std::atomic<bool> stop(false);
//
//	auto serialized_handshake_pubkey = ecdh_ChaCha20_Poly1305::serialize(handshake_keypair.pubkey.data(), handshake_keypair.pubkey.size());
//	auto exec = [&] () {
//			std::cout << "1 ";
//			std::cout.flush();
//			while (!stop && !end) {
//				std::cout << "2 ";
//				std::cout.flush();
//				connection.send(serialized_handshake_pubkey); // TODO
//				if (connection.has_messages()) {
//					std::cout << "3 ";
//					std::cout.flush();
//					auto msg = connection.pop_message();
//					std::cout << "msg: " << msg << '\n';
//					std::cout.flush();
//					if (msg.size() == crypto_box_PUBLICKEYBYTES) {
//						return msg;
//					}
//				}
//				std::cout << "4 ";
//				std::cout.flush();
//				std::this_thread::yield();
//			}
//			throw std::runtime_error("handshake failed");
//	};
//
//	auto task = std::packaged_task<std::string ()>(exec);
//	auto handle = task.get_future();
//
//	if (handle.wait_for(std::chrono::seconds(100000)) == std::future_status::timeout) {
//		stop = true;
//		std::this_thread::sleep_for(std::chrono::seconds(1));
//	} else {
//		auto handshake_pubkey = ecdh_ChaCha20_Poly1305::deserialize_pubkey(handle.get());
//		auto result = ecdh_ChaCha20_Poly1305::generate_nonce_with(handshake_keypair, handshake_pubkey);
//		std::cout << "done\n";
//		logger << "done\n";
//		return result;
//	}
//	throw std::runtime_error("handshake failed");
//}

ecdh_ChaCha20_Poly1305::nonce_t do_handshake (const std::string &ipv6_addr,
				const ecdh_ChaCha20_Poly1305::pubkey_t &pubkey,
				c_UDPasync &connection) {

	std::cout << "handshake started...\n";
	logger << "handshake started...\n";
	auto my_handshake_keypair = ecdh_ChaCha20_Poly1305::generate_keypair();
	std::string handshake_pubkey;

	auto my_handshake_pubkey = ecdh_ChaCha20_Poly1305::serialize(my_handshake_keypair.pubkey.data(), my_handshake_keypair.pubkey.size());
	connection.send(my_handshake_pubkey);

	while (!end) {
		if (connection.has_messages()) {
			auto msg = connection.pop_message();
			if (msg.size() == crypto_box_PUBLICKEYBYTES * 2) {
				handshake_pubkey = msg;
				break;
			}
		}
	}

	auto deserialized_handshake_pubkey = ecdh_ChaCha20_Poly1305::deserialize_pubkey(handshake_pubkey);

	auto result = ecdh_ChaCha20_Poly1305::generate_nonce_with(my_handshake_keypair, deserialized_handshake_pubkey);
	std::cout << "done\n";
	logger << "done\n";
	return result;
}

void do_prehandshake (c_UDPasync &connection) { // TODO
	connection.send("");

	while (!connection.has_messages()) {
		connection.send("");
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}

	std::this_thread::sleep_for(std::chrono::seconds(1));
	connection.send("");
}

void connect (const std::string &ipv6_addr,
				const ecdh_ChaCha20_Poly1305::pubkey_t &pubkey,
				const ecdh_ChaCha20_Poly1305::keypair_t &keypair) { // TODO

	end = false;
	signal(SIGINT, [] (int) {
			logger << "aborting...";
			end = true;
			logger.close();
	});

	ecdh_ChaCha20_Poly1305::init();
	c_UDPasync connection(ipv6_addr, 12325, 12325);

	logger << "connecting...\n";
	std::cout << "connecting...\n";
	do_prehandshake(connection);
	std::cout << "connected with " << ipv6_addr << '\n';
	logger << "connected with " << ipv6_addr << '\n';

	ecdh_ChaCha20_Poly1305::sharedkey_t shared_key = ecdh_ChaCha20_Poly1305::generate_sharedkey_with(keypair, pubkey);

	ecdh_ChaCha20_Poly1305::nonce_t nonce = do_handshake(ipv6_addr, pubkey, connection);

	logger << "sharedkey: ";
	for (auto &&c: shared_key) {
		logger << int(c) << ' ';
	}
	logger << "\nnonce: ";
	for (auto &&c: nonce) {
		logger << int(c) << ' ';
	}
	logger << "\n\n";

	std::thread receive(start_recieving, std::ref(connection), std::ref(shared_key), std::ref(nonce));
	std::thread send(handle_sending, std::ref(connection), std::ref(shared_key), std::ref(nonce));
	receive.join();
	send.join();
}

void debug () {
	std::cout << "DEBUG MODE\n";
	std::string ipv6_addr, pubkey, config_filename;
	std::cin >> ipv6_addr >> pubkey >> config_filename;
	auto keypair = load_keypair(config_filename);
	connect(ipv6_addr, ecdh_ChaCha20_Poly1305::deserialize_pubkey(pubkey), keypair);
}

void start (int argc, char **argv) {
	if (argc < 2) {
		//		std::cout << "type --help to show help\n";
		//		return;
		debug();
	}

	std::string command = std::string(argv[1]);

	if (command == "--help") {
		std::cout << "--help                                       show this help\n";
		std::cout << "--connect [ipv6] [pubkey] [config filename]  connect to [ipv6]\n";
		std::cout << "--gen-conf [config filename]                 generate keypair and save to [config filename]\n";

	} else if (command == "--connect") {
		if (argc < 5) {
			std::cout << "type --help to show help\n";
			return;
		}
		std::string ipv6_addr = std::string(argv[2]);
		ecdh_ChaCha20_Poly1305::pubkey_t pubkey = ecdh_ChaCha20_Poly1305::deserialize_pubkey(std::string(argv[3]));
		std::string config_filename = std::string(argv[4]);
		auto keypair = load_keypair(config_filename);
		connect(ipv6_addr, pubkey, keypair);

	} else if (command == "--gen-conf") {
		if (argc < 3) {
			std::cout << "type --help to show help\n";
			return;
		}
		std::string filename = std::string(argv[2]);
		generate_config(filename);

	} else if (command == "--debug") {
		debug();

	} else {
		std::cout << "type --help to show help\n";
	}
}

int main (int argc, char **argv) {
	try {
		start(argc, argv);
	} catch (std::exception &exc) {
		std::cout << exc.what() << '\n';
	} catch (...) {
		std::cout << "internal error\n";
	}
	return 0;
}
