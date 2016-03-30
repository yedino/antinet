#include "ecdh_ChaCha20_Poly1305.hpp"

namespace ecdh_ChaCha20_Poly1305 {
		std::string serialize (const unsigned char *data, size_t size) {
			std::stringstream result;
			for (size_t i = 0; i < size; ++i) {
				result << std::setfill('0') << std::setw(2) << std::hex << int(data[i]);
			}
			return result.str();
		}

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

		sharedkey_t generate_sharedkey_with (const keypair_t &keypair, const pubkey_t &pubkey) {
			sharedkey_t sharedkey;
			unsigned char scalar[crypto_scalarmult_BYTES];

			if (crypto_scalarmult(scalar, keypair.privkey.data(), pubkey.data()) != 0) {
				throw std::runtime_error("ERROR while generating shared key");
			}

			const unsigned char *first = nullptr, *second = nullptr;
			for (size_t i = 0; i < keypair.pubkey.size(); ++i) {
				if (keypair.pubkey.at(i) < pubkey.at(i)) {
					first = keypair.pubkey.data();
					second = pubkey.data();
				} else if (keypair.pubkey.at(i) > pubkey.at(i)) {
					first = pubkey.data();
					second = keypair.pubkey.data();
				}
			}
			if (!first || !second) {
				throw std::runtime_error("error: pubkeys are equal!");
			}

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
			return ""; // TODO
		}

		std::string encrypt (const std::string &data,
						const sharedkey_t &sharedkey,
						const nonce_t &nonce) {

			return encrypt(data.data(), data.size(), sharedkey, nonce);
		}

		std::string encrypt (const char *data, size_t size,
						const sharedkey_t &sharedkey,
						const nonce_t &nonce) {

			assert(crypto_generichash_BYTES >= crypto_aead_chacha20poly1305_KEYBYTES);

			std::unique_ptr<unsigned char[]> ciphertext(new unsigned char[crypto_aead_chacha20poly1305_ABYTES + size]);
			std::string additional_data = generate_additional_data(data);

			unsigned long long ciphertext_len = 0;
			crypto_aead_chacha20poly1305_encrypt(ciphertext.get(), &ciphertext_len,
			                                     (const unsigned char *)data, size,
			                                     (const unsigned char *)additional_data.c_str(), additional_data.size(),
			                                     NULL, nonce.data(), sharedkey.data());

			return std::string((const char *)ciphertext.get(), ciphertext_len);
			// TODO update nonce
		}

		std::string decrypt (const std::string &ciphertext,
						const sharedkey_t &sharedkey,
						const nonce_t &nonce) {

			return decrypt(reinterpret_cast<const unsigned char *>(ciphertext.data()), ciphertext.size(), sharedkey, nonce);
		}


		std::string decrypt (const unsigned char *ciphertext, size_t size,
						const sharedkey_t &sharedkey,
						const nonce_t &nonce) {

			unsigned char decrypted[100000]; // TODO [p] len of msg
			unsigned long long decrypted_len;
			std::string additional_data = generate_additional_data("");

			if (crypto_aead_chacha20poly1305_decrypt(decrypted, &decrypted_len,
			                                         NULL,
			                                         ciphertext, size,
			                                         (const unsigned char *)additional_data.c_str(),
			                                         additional_data.size(),
			                                         nonce.data(), sharedkey.data()) != 0) {

				throw std::runtime_error("msg decryption failed");
			}

			return std::string((const char *)decrypted, decrypted_len);
		}
}
