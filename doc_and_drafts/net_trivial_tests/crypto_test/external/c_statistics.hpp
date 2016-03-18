#ifndef SERVER_STATISTICS_HPP
#define SERVER_STATISTICS_HPP
#include <atomic>
#include <iostream>
#include <array>
#include <sstream>
#include <iomanip>


struct c_statistics {
private:
		std::atomic_uint_fast32_t received_messages;
		std::atomic_uint_fast32_t sent_messages;

		std::atomic_uint_fast32_t received_bytes;
		std::atomic_uint_fast32_t sent_bytes;
public:
		c_statistics ();

		c_statistics (const c_statistics &other);

		size_t get_received_messages () const;

		size_t get_received_bytes () const;

		size_t get_sent_messages () const;

		size_t get_sent_bytes () const;

		void register_sent_message (int32_t);

		void register_received_message (int32_t);

};

std::ostream &operator<< (std::ostream &, const c_statistics &);


#endif //SERVER_STATISTICS_HPP
