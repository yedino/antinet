#include "c_statistics.hpp"

c_statistics::c_statistics () : received_messages(0), sent_messages(0), received_bytes(0), sent_bytes(0) { }

c_statistics::c_statistics (const c_statistics &other)
	: received_messages(other.get_received_messages()),
		sent_messages(other.get_sent_messages()),
		received_bytes(other.get_received_bytes()),
		sent_bytes(other.get_sent_bytes()) { }

size_t c_statistics::get_received_messages () const { return received_messages; }

size_t c_statistics::get_received_bytes () const { return received_bytes; }

size_t c_statistics::get_sent_messages () const { return sent_messages; }

size_t c_statistics::get_sent_bytes () const { return sent_bytes; }

void c_statistics::register_sent_message (int32_t num_bytes) {
	++sent_messages;
	sent_bytes.fetch_add(num_bytes);
}

void c_statistics::register_received_message (int32_t messageSize) {
	++received_messages;
	received_bytes.fetch_add(messageSize);
}

std::string data_size_to_string (uint64_t size) {
	std::array<const char *, 4> sizeStrings = {"B", "KB", "MB", "GB"};
	for (int i = sizeStrings.size() - 1; i >= 0; --i) {
		auto referenceSize = size_t(1 << i * 10);
		if (size < referenceSize)
			continue;

		auto scaledSize = static_cast<double>(size) / static_cast<double>(referenceSize);
		std::ostringstream oss;
		oss << std::setprecision(2) << static_cast<uint32_t>(scaledSize) << sizeStrings[i];
		return oss.str();
	}
	return std::to_string(size) + " bytes";
}

std::ostream &operator<< (std::ostream &os, const c_statistics &stat) {
	os << "Sent " << stat.get_sent_messages() << " msgs (" << data_size_to_string(stat.get_sent_bytes()) << ") ";
	os << "Rcvd " << stat.get_received_messages() << " msgs (" << data_size_to_string(stat.get_received_bytes()) << ")";
	return os;
}