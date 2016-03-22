#ifndef UNTITLED_ECDH_CHACHA20_POLY1305_HPP
#define UNTITLED_ECDH_CHACHA20_POLY1305_HPP
#include <sodium.h>
#include <array>
#include <memory>
#include <cassert>
#include <iomanip>
#include <sstream>

namespace ecdh_ChaCha20_Poly1305 {
		typedef std::array<unsigned char, crypto_box_PUBLICKEYBYTES> pubkey_t;
		typedef std::array<unsigned char, crypto_box_SECRETKEYBYTES> privkey_t;
		typedef std::array<unsigned char, crypto_generichash_BYTES> sharedkey_t;
		typedef std::array<unsigned char, crypto_aead_chacha20poly1305_NPUBBYTES> nonce_t;

		struct keypair_t {
				privkey_t privkey;
				pubkey_t pubkey;
		};

		std::string serialize (const unsigned char *data, size_t size) {
			std::stringstream result;
			for (size_t i = 0; i < size; ++i) {
				result << std::setfill('0') << std::setw(2) << std::hex << int(data[i]);
			}
			return result.str();
		}

		template <size_t N>
		std::array<unsigned char, N> deserialize (const std::string &data) {
			std::array<unsigned char, N> result;

			for (size_t i = 0, j = 0; i + 1 < data.size() && j < result.size(); i += 2, ++j) {
				int r = std::stoi(data.substr(i, 2), nullptr, 16);
				result.at(j) = r;
			}
			return result;
		}

		auto deserialize_pubkey = deserialize<crypto_box_PUBLICKEYBYTES>; // TODO
		auto deserialize_privkey = deserialize<crypto_box_SECRETKEYBYTES>; // TODO

		void init () {
			if (sodium_init() == -1) {
				throw std::runtime_error("libsodium init error!");
			}
		}

		keypair_t generate_keypair () {
			privkey_t privkey;
			pubkey_t pubkey;

			randombytes_buf(privkey.data(), crypto_box_SECRETKEYBYTES);
			crypto_scalarmult_base(pubkey.data(), privkey.data());
			return {std::move(privkey), std::move(pubkey)};
		}

		const unsigned char *get_first_pubkey_to_hash (const pubkey_t &a, const pubkey_t &b) {
			for (size_t i = 0; i < a.size(); ++i) {
				if (a.at(i) < b.at(i)) {
					return a.data();
				} else if (a.at(i) > b.at(i)) {
					return b.data();
				}
			}

			throw std::runtime_error("error: pubkeys are equal!");
		}

		sharedkey_t generate_sharedkey_with (const keypair_t &keypair, const pubkey_t &pubkey) {
			sharedkey_t sharedkey;
			unsigned char scalar[crypto_scalarmult_BYTES];

			if (crypto_scalarmult(scalar, keypair.privkey.data(), pubkey.data()) != 0) {
				throw std::runtime_error("ERROR while generating shared key");
			}

			const unsigned char *first = get_first_pubkey_to_hash(keypair.pubkey, pubkey);
			assert (first != nullptr);
			const unsigned char *second = (first == keypair.pubkey.data() ? pubkey.data() : keypair.pubkey.data());
			assert(first != second);
			assert(second != nullptr);

			crypto_generichash_state h;
			crypto_generichash_init(&h, NULL, 0U, crypto_generichash_BYTES);
			crypto_generichash_update(&h, scalar, crypto_scalarmult_BYTES);
			crypto_generichash_update(&h, first, crypto_box_PUBLICKEYBYTES);
			crypto_generichash_update(&h, second, crypto_box_PUBLICKEYBYTES);
			crypto_generichash_final(&h, sharedkey.data(), crypto_generichash_BYTES);

			return sharedkey;
		}

		nonce_t generate_nonce_with (const keypair_t &keypair, const pubkey_t &pubkey) {
			auto sharedkey = generate_sharedkey_with(keypair, pubkey);
			nonce_t result;
			for (size_t i = 0; i < result.size() && i < sharedkey.size(); ++i) {
				result.at(i) = sharedkey.at(i);
			}

			return result;
		}


		std::string generate_additional_data (const std::string &data) {
			return "bebebebebe"; // TODO
		}

		std::string encrypt (const std::string &data,
						const sharedkey_t &sharedkey,
						const nonce_t &nonce) {

			assert(crypto_generichash_BYTES >= crypto_aead_chacha20poly1305_KEYBYTES);

			std::unique_ptr<unsigned char[]> ciphertext(new unsigned char[crypto_aead_chacha20poly1305_ABYTES + data.size()]);
			std::string additional_data = generate_additional_data(data);

			unsigned long long ciphertext_len = 0;
			crypto_aead_chacha20poly1305_encrypt(ciphertext.get(), &ciphertext_len,
			                                     (const unsigned char *)data.c_str(), data.size(),
			                                     (const unsigned char *)additional_data.c_str(), additional_data.size(),
			                                     NULL, nonce.data(), sharedkey.data());

			return std::string((const char *)ciphertext.get(), ciphertext_len);
			// TODO update nonce
		}

		std::string decrypt (const std::string &ciphertext,
						const sharedkey_t &sharedkey,
						const nonce_t &nonce) {

			unsigned char decrypted[100000]; // TODO len of msg
			unsigned long long decrypted_len;
			std::string additional_data = generate_additional_data(""); // TODO

			if (crypto_aead_chacha20poly1305_decrypt(decrypted, &decrypted_len,
			                                         NULL,
			                                         (const unsigned char *)ciphertext.c_str(), ciphertext.size(),
			                                         (const unsigned char *)additional_data.c_str(),
			                                         additional_data.size(),
			                                         nonce.data(), sharedkey.data()) != 0) {

				return "message forged!";
			}

			if (!decrypted) {
				throw std::runtime_error("'decrypted' is null!");
			}

			return std::string((const char *)decrypted, decrypted_len);
		}
};

#endif //UNTITLED_ECDH_CHACHA20_POLY1305_HPP
