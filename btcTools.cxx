/* btcTools.cxx */
/* ====================================================================
 * INCLUDE ALL BITCOIN RELATED FUNCTIONS FOR THIS PROJECT.
 * DO NOT USE DIRECTLY; ONLY USE BY INCLUDING.
 * ====================================================================
 *
 * FUNCTIONS EXPLAINED:
 *
 * #1 uint256_t urandom_256():
 *    Generate a random 256-bit unsigned integer which serves as a Bitcoin
 *    private key. Cryptographically secure URANDOM engine is needed
 *    for the function. Return the large number.
 *
 * #2 string priv_to_wif_comp(uint256_t):
 *    Convert a Bitcoin private key into Wallet Import Format-compressed
 *    (string starts with K or L). Return the encoded key string.
 *
 * #3 uint256_t wif_to_priv(string):
 *    Convert a WIF-compressed key into its raw format(256-bit integer).
 *    Can process WIF-uncompressed keys but not used for this project.
 *    Return the large number.
 *
 * #4 string wif_comp_to_pkh(string):
 *    Derive the public key from the WIF-compressed using elliptical curve
 *    cryptography specified in Bitcoin; then use one way hash functions
 *    and base58 check encoding to produce a standard Bitcoin address
 *    (string starts with 1). Return the address.
 *
 * #5 string wif_comp_to_cipher6p(string, string):
 *    Consume a WIF-compressed key and produce a encrypted cipher based
 *    roughly on the BIP-38 standard with a slight change in KDF; instead
 *    of using scrypt, SHA512 is chosen to generate the key for AES256
 *    encryption. Flag byte is set to be 0xF0 which causes the cipher to
 *    begin with "6Pb/6Pc". Return the cipher string.
 *
 * #6 uint256_t cipher6p_decrypt(string, string):
 *    Use a password to convert the cipher string back into the raw private key.
 *    This process does not automatically verify the passowrd in execution.
 *    Wrong password will produce a wrong private key. Return the large number.
 *
 * #7 int get_ecdsa_sig(unsigned char*, int, unsigned char*, unsigned char**):
 *    Use the given message array and the private key to produce a ECDSA
 *    signature which complies with the Bitcoin consensus rules. It is used
 *    to authorize the spending of Bitcoin available to this wallet. The
 *    signature data is in DER encoding. Return the length of the signature.
 *
 * #8 void get_output_serial(std::string, double, unsigned char*):
 *    Generate a serialized output data for a raw transaction.
 *    Locking script is a simple P2PKH script. Return nothing.
 *
 * #9 string create_raw_transaction(vector<UTXO>&, vector<string>&, string, string, double, double):
 *    Respond to a send Bitcoin request from the user by generating a raw
 *    transaction data chunk which can be directly mined by the network.
 *    UTXOs chosen to be used as inputs will be voided after the transaction is
 *    created. It only supports sending Bitcoin to one recipient's address and
 *    will automatically generate a change output to refund the user the
 *    remaining balance(minus fee). The change output will be credited to the
 *    wallet's balance with the user's consent.
 *
 * #
 *
 *
 */

#include "btcStructs.h"
#include "btcTools.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cmath>
#include <iomanip>
#include <sstream>

using namespace std;
using namespace boost::multiprecision;

typedef vector<unsigned char>::iterator vbit;


uint256_t urandom_256() {

	uint256_t real_key;
	uint256_t part_1, part_2, part_3, part_4;
	long part;
	size_t part_size = sizeof(part);

	ifstream urandom("/dev/urandom", ios::in|ios::binary);
	if (urandom) {
		urandom.read(reinterpret_cast<char*>(&part_1), part_size);
		urandom.read(reinterpret_cast<char*>(&part_2), part_size);
		urandom.read(reinterpret_cast<char*>(&part_3), part_size);
		urandom.read(reinterpret_cast<char*>(&part_4), part_size);
		}
	urandom.close();

	real_key += part_4 << 192;
	real_key += part_3 << 128;
	real_key += part_2 << 64;
	real_key += part_1;

	return real_key;

	}


string priv_to_wif_comp(uint256_t t_raw_key) {

	vector<unsigned char> main_stream;
	main_stream.push_back(0x80);

	uint256_t chunk;
	unsigned char temp_byte = 0;
	for (int i = 31; i >= 0; --i) {
		chunk = (t_raw_key >> (i * 8)) & 0xFF;

		while (chunk > 0) {
			temp_byte += 1;
			--chunk;
			}

		main_stream.push_back(temp_byte);
		temp_byte = 0;
		}
	main_stream.push_back(0x01);

	unsigned char hash_one[SHA256_DIGEST_LENGTH];
	SHA256_CTX hash_state;
	SHA256_Init(&hash_state);
	for (vbit iit = main_stream.begin(); iit != main_stream.end(); ++iit) {
		SHA256_Update(&hash_state, &(*iit), 1);
		}
	SHA256_Final(hash_one, &hash_state);

	unsigned char hash_two[SHA256_DIGEST_LENGTH];
	SHA256_Init(&hash_state);
	for (int j = 0; j < 32; ++j) {
		SHA256_Update(&hash_state, &(hash_one[j]), 1);
		}
	SHA256_Final(hash_two, &hash_state);

	vector<unsigned char> check_sum;
	for (int k = 0; k < 4; ++k) {
		check_sum.push_back(hash_two[k]);
		main_stream.push_back(hash_two[k]);
		}

	const string encoder = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	uint512_t long_key;
	uint512_t shifter;
	int sfcounter = 37;
	for (vbit kkt = main_stream.begin(); kkt != main_stream.end(); ++kkt) {
		shifter = *kkt;
		long_key += (shifter << (sfcounter * 8));
		sfcounter -= 1;
		}

	string final_code = "";
	vector<char> parts;
	uint512_t temp_modulo;
	int modulo = 0;

	while (long_key > 0) {
		temp_modulo = long_key % 58;
		long_key -= temp_modulo;
		long_key /= 58;

		while (temp_modulo > 0) {
			modulo += 1;
			temp_modulo -= 1;
			}

		parts.push_back(encoder[modulo]);
		modulo = 0;
		}

	for (int l = parts.size() - 1; l >= 0; --l) {
		final_code += parts[l];
		}

	return final_code;

	}


uint256_t wif_to_priv(string t_wif_key) {

	uint256_t priv_key;
	string const decoder = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	bool comp;
	if (t_wif_key.find("5") == 0) {
		comp = false;
		} else {comp = true;}

	uint512_t long_key;
	char code;
	int index;
	int power;
	uint512_t chunk;
	for (size_t i = 0; i < t_wif_key.length(); ++i) {
		code = t_wif_key[i];
		index = decoder.find(code);
		power = (t_wif_key.length() - 1) - i;
		chunk = 58;
		chunk = pow(chunk, power) * index;
		long_key += chunk;
		}

	vector<unsigned char> long_stream;
	vector<unsigned char> checksum;
	unsigned char ibyte = 0;
	uint512_t trunc;
	for (int j = 36; j >= 0; --j) {
		trunc = (long_key >> (j * 8)) & 0xFF;

		while (trunc > 0) {
			ibyte += 1;
			trunc -= 1;
			}

		if (j < 4) {
			checksum.push_back(ibyte);
			}else {
				if (comp and j != 4) {long_stream.push_back(ibyte);}
				else if (not comp and j != 36) {long_stream.push_back(ibyte);}
				}
		ibyte = 0;
		}

	uint256_t key_part;
	int shifter = 31;
	for (vbit kkt = long_stream.begin(); kkt != long_stream.end(); ++kkt) {
		key_part = *kkt;
		key_part = (key_part << shifter * 8);
		priv_key += key_part;
		shifter -= 1;
		}

	return priv_key;

	}


string wif_comp_to_pkh(string t_wif_comp) {

	string final_address;
	uint256_t raw_key;
	raw_key = wif_to_priv(t_wif_comp);

	unsigned char priv_key[32];
	unsigned char tbt = 0;
	uint256_t tchunk;
	for (int i = 0; i < 32; ++i) {
		tchunk = (raw_key >> ((31 - i) * 8)) & 0xFF;

		while (tchunk > 0) {
			++tbt;
			--tchunk;
			}

		priv_key[i] = tbt;
		tbt = 0;
		}

	unsigned char pub_key[33];
	size_t klen = 33;

	EC_GROUP *ec256;
	ec256 = EC_GROUP_new_by_curve_name(NID_secp256k1);

	BN_CTX *ctx;
	ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	BIGNUM *bn_priv;
	bn_priv = BN_new();
	BN_bin2bn(priv_key, 32, bn_priv);

	EC_POINT *pt_pub;
	pt_pub = EC_POINT_new(ec256);

	EC_POINT_mul(ec256, pt_pub, bn_priv, NULL, NULL, ctx);
	EC_POINT_point2oct(ec256, pt_pub, POINT_CONVERSION_COMPRESSED,
					   pub_key, klen, ctx);

	SHA256_CTX SH;
	SHA256_CTX *sha_state = &SH;
	unsigned char sha_one[SHA256_DIGEST_LENGTH];
	SHA256_Init(sha_state);
	for (int j = 0; j < 33; ++j) {
		SHA256_Update(sha_state, &pub_key[j], 1);
		}
	SHA256_Final(sha_one, sha_state);

	RIPEMD160_CTX RIP;
	RIPEMD160_CTX *rip_state = &RIP;
	unsigned char rip_one[RIPEMD160_DIGEST_LENGTH];
	RIPEMD160_Init(rip_state);
	for (int k = 0; k < 32; ++k) {
		RIPEMD160_Update(rip_state, &sha_one[k], 1);
		}
	RIPEMD160_Final(rip_one, rip_state);

	unsigned char ex_pub_key[25];
	ex_pub_key[0] = 0x00;

	unsigned char sha_two[32];
	unsigned char sha_three[32];
	SHA256_Init(sha_state);
	SHA256_Update(sha_state, &ex_pub_key[0], 1);
	for (int l = 0; l < 20; ++l) {
		SHA256_Update(sha_state, &rip_one[l], 1);
		}
	SHA256_Final(sha_two, sha_state);

	SHA256_Init(sha_state);
	for (int m = 0; m < 32; ++m) {
		SHA256_Update(sha_state, &sha_two[m], 1);
		}
	SHA256_Final(sha_three, sha_state);

	for (int n = 0; n < 20; ++n) {
		ex_pub_key[n + 1] = rip_one[n];
		}
	for (int o = 0; o < 4; ++o) {
		ex_pub_key[o + 21] = sha_three[o];
		}

	const string encoder = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	int lead_zero_count = 0;
	while (ex_pub_key[lead_zero_count] == 0x00) {
		final_address += "1";
		lead_zero_count += 1;
		}

	uint256_t bn_ex_key;
	uint256_t tchunk2;
	for (int p = 0; p < 25; ++p) {
		tchunk2 = ex_pub_key[p];
		tchunk2 = tchunk2 << ((24 - p) * 8);
		bn_ex_key += tchunk2;
		}

	vector<char> address_char;
	int modu = 0;
	uint256_t mchunk;
	while (bn_ex_key > 0) {
		mchunk = bn_ex_key % 58;
		bn_ex_key -= mchunk;
		bn_ex_key /= 58;
		while (mchunk > 0) {
			modu += 1;
			mchunk -= 1;
			}
		address_char.push_back(encoder[modu]);
		modu = 0;
		}

	for (int q = address_char.size() - 1; q >= 0; --q) {
		final_address += address_char[q];
		}

	return final_address;

	}


string wif_comp_to_cipher6p(string t_wif_comp, string t_password) {

	string address;
	size_t addr_len;

	unsigned char pre1 = 0x01;
	unsigned char pre2 = 0x42;
	unsigned char flag = 0xF0;

	address = wif_comp_to_pkh(t_wif_comp);
	addr_len = address.length();
	unsigned char addr_bytes[addr_len];
	copy(address.begin(), address.end(), addr_bytes);

	unsigned char saltsha1[32];
	unsigned char saltsha2[32];
	SHA256_CTX sha_state;
	SHA256_Init(&sha_state);
	for (size_t i = 0; i < addr_len; ++i) {
		SHA256_Update(&sha_state, &addr_bytes[i], 1);
		}
	SHA256_Final(saltsha1, &sha_state);

	SHA256_Init(&sha_state);
	for (int j = 0; j < 32; ++j) {
		SHA256_Update(&sha_state, &saltsha1[j], 1);
		}
	SHA256_Final(saltsha2, &sha_state);

	const unsigned char addr_hash[4] = {saltsha2[0], saltsha2[1],
										saltsha2[2], saltsha2[3]};

	// !! USE SHA512 INSTEAD OF SCRYPT TO DERIVE THE KEY !!
	unsigned char keyout[SHA512_DIGEST_LENGTH];

	unsigned char dh1[32];
	unsigned char dh2[32];

	size_t pass_len = t_password.length();
	unsigned char password[pass_len];
	copy(t_password.begin(), t_password.end(), password);

	SHA512_CTX ss512;
	SHA512_Init(&ss512);
	SHA512_Update(&ss512, &addr_hash[0], 1);
	SHA512_Update(&ss512, &addr_hash[1], 1);
	SHA512_Update(&ss512, &addr_hash[2], 1);
	SHA512_Update(&ss512, &addr_hash[3], 1);
	for (size_t i = 0; i < pass_len; ++i) {
		SHA512_Update(&ss512, &password[i], 1);
		}
	SHA512_Final(keyout, &ss512);

	for (int j = 0; j < 32; ++j) {
		dh1[j] = keyout[j];
		dh2[j] = keyout[j + 32];
		}

	const unsigned char r_key2[32] = {
		dh2[0], dh2[1], dh2[2], dh2[3], dh2[4], dh2[5],
		dh2[6], dh2[7], dh2[8], dh2[9], dh2[10], dh2[11],
		dh2[12], dh2[13], dh2[14], dh2[15], dh2[16], dh2[17],
		dh2[18], dh2[19], dh2[20], dh2[21], dh2[22], dh2[23],
		dh2[24], dh2[25], dh2[26], dh2[27], dh2[28], dh2[29],
		dh2[30], dh2[31]};
	const unsigned char* key2 = r_key2;

	uint256_t raw_key = wif_to_priv(t_wif_comp);
	unsigned char priv_key[32];
	unsigned char tbt = 0;
	uint256_t tchunk;
	for (int i = 0; i < 32; ++i) {
		tchunk = (raw_key >> ((31 - i) * 8)) & 0xFF;
		while (tchunk > 0) {
			++tbt;
			--tchunk;}
		priv_key[i] = tbt;
		tbt = 0;}

	unsigned char tempb1[16];
	unsigned char tempb2[16];
	for (int j = 0; j < 16; ++j) {
		tempb1[j] = priv_key[j] ^ dh1[j];
		tempb2[j] = priv_key[j + 16] ^ dh1[j + 16];
		}
	const unsigned char r_block1[16] = {
		tempb1[0], tempb1[1], tempb1[2], tempb1[3], tempb1[4], tempb1[5],
		tempb1[6], tempb1[7], tempb1[8], tempb1[9], tempb1[10], tempb1[11],
		tempb1[12], tempb1[13], tempb1[14], tempb1[15]};
	const unsigned char r_block2[16] = {
		tempb2[0], tempb2[1], tempb2[2], tempb2[3], tempb2[4], tempb2[5],
		tempb2[6], tempb2[7], tempb2[8], tempb2[9], tempb2[10], tempb2[11],
		tempb2[12], tempb2[13], tempb2[14], tempb2[15]};

	const unsigned char* block1 = r_block1;
	const unsigned char* block2 = r_block2;
	int block_len = 16;

	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX *ctx2;
	ctx2 = EVP_CIPHER_CTX_new();

	unsigned char eh1[16];
	unsigned char eh2[16];
	unsigned char* eout1 = eh1;
	unsigned char* eout2 = eh2;
	int eh_len = sizeof(eh1);

	EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key2, NULL);
	EVP_EncryptUpdate(ctx, eout1, &eh_len, block1, block_len);
	EVP_CIPHER_CTX_free(ctx);

	EVP_EncryptInit(ctx2, EVP_aes_256_cbc(), key2, NULL);
	EVP_EncryptUpdate(ctx2, eout2, &eh_len, block2, block_len);
	EVP_CIPHER_CTX_free(ctx2);

	vector<unsigned char> cipher_stream;
	cipher_stream.push_back(pre1);
	cipher_stream.push_back(pre2);
	cipher_stream.push_back(flag);
	cipher_stream.push_back(addr_hash[0]);
	cipher_stream.push_back(addr_hash[1]);
	cipher_stream.push_back(addr_hash[2]);
	cipher_stream.push_back(addr_hash[3]);

	for (int i = 0; i < 16; ++i) {cipher_stream.push_back(eh1[i]);}
	for (int i = 0; i < 16; ++i) {cipher_stream.push_back(eh2[i]);}
	assert (cipher_stream.size() == 39);

	unsigned char csm[SHA256_DIGEST_LENGTH];
	SHA256_Init(&sha_state);
	for (size_t j = 0; j < cipher_stream.size(); ++j) {
		SHA256_Update(&sha_state, &cipher_stream[j], 1);}
	SHA256_Final(csm, &sha_state);

	cipher_stream.push_back(csm[0]);
	cipher_stream.push_back(csm[1]);
	cipher_stream.push_back(csm[2]);
	cipher_stream.push_back(csm[3]);
	assert (cipher_stream.size() == 43);

	const string encoder = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	uint512_t long_key;
	uint512_t shifter;
	int sfcounter = 42;
	for (vbit iit = cipher_stream.begin(); iit != cipher_stream.end(); ++iit) {
		shifter = *iit;
		long_key += (shifter << (sfcounter * 8));
		sfcounter -= 1;
		}

	string final_cipher;
	vector<char> parts;
	uint512_t temp_modulo;
	int modulo = 0;

	while (long_key > 0) {
		temp_modulo = long_key % 58;
		long_key -= temp_modulo;
		long_key /= 58;

		while (temp_modulo > 0) {
			modulo += 1;
			temp_modulo -= 1;
			}

		parts.push_back(encoder[modulo]);
		modulo = 0;
		}

	for (int i = parts.size() - 1; i >= 0; --i) {final_cipher += parts[i];}

	return final_cipher;

	}


uint256_t cipher6p_decrypt(string t_cipher6p, string t_password) {

	int cp_len = t_cipher6p.length();

	const string decoder = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	uint512_t bn_cipher, chunk = 58;
	int value;
	for (int i = cp_len - 1; i > -1; --i) {
		value = decoder.find(t_cipher6p[cp_len - 1 - i]);
		chunk = pow(chunk, i) * value;
		bn_cipher += chunk;
		chunk = 58;
		}

	vector<unsigned char> cipher_bytes;
	unsigned char cbyte = 0;
	chunk = 0;
	for (int j = 42; j > -1; --j) {
		chunk = (bn_cipher >> (j * 8)) & 0xFF;
		while (chunk > 0) {++cbyte; --chunk;}
		cipher_bytes.push_back(cbyte);
		cbyte = 0;
		}

	const unsigned char salt[4] = {cipher_bytes[3], cipher_bytes[4],
								   cipher_bytes[5], cipher_bytes[6]};

	unsigned char password[t_password.length()];
	copy(t_password.begin(), t_password.end(), password);

	const unsigned char eh1[16] = {
		cipher_bytes[7], cipher_bytes[8], cipher_bytes[9], cipher_bytes[10],
		cipher_bytes[11], cipher_bytes[12], cipher_bytes[13], cipher_bytes[14],
		cipher_bytes[15], cipher_bytes[16], cipher_bytes[17], cipher_bytes[18],
		cipher_bytes[19], cipher_bytes[20], cipher_bytes[21], cipher_bytes[22]};
	const unsigned char eh2[16] = {
		cipher_bytes[23], cipher_bytes[24], cipher_bytes[25], cipher_bytes[26],
		cipher_bytes[27], cipher_bytes[28], cipher_bytes[29], cipher_bytes[30],
		cipher_bytes[31], cipher_bytes[32], cipher_bytes[33], cipher_bytes[34],
		cipher_bytes[35], cipher_bytes[36], cipher_bytes[37], cipher_bytes[38]};
	const unsigned char* dblock1 = eh1;
	const unsigned char* dblock2 = eh2;

	unsigned char full_key[SHA512_DIGEST_LENGTH];
	unsigned char d1h1[16];
	unsigned char d1h2[16];
	SHA512_CTX ss512;
	SHA512_Init(&ss512);
	SHA512_Update(&ss512, &salt[0], 1);
	SHA512_Update(&ss512, &salt[1], 1);
	SHA512_Update(&ss512, &salt[2], 1);
	SHA512_Update(&ss512, &salt[3], 1);
	for (size_t i = 0; i < t_password.length(); ++i) {
		SHA512_Update(&ss512, &password[i], 1);}
	SHA512_Final(full_key, &ss512);

	for (int j = 0; j < 16; ++j) {
		d1h1[j] = full_key[j];
		d1h2[j] = full_key[j + 16];
		}

	const unsigned char d2h[32] = {
		full_key[32], full_key[33], full_key[34], full_key[35],
		full_key[36], full_key[37], full_key[38], full_key[39],
		full_key[40], full_key[41], full_key[42], full_key[43],
		full_key[44], full_key[45], full_key[46], full_key[47],
		full_key[48], full_key[49], full_key[50], full_key[51],
		full_key[52], full_key[53], full_key[54], full_key[55],
		full_key[56], full_key[57], full_key[58], full_key[59],
		full_key[60], full_key[61], full_key[62], full_key[63]
		};
	const unsigned char* dhkey = d2h;

	unsigned char result1[16];
	unsigned char result2[16];
	unsigned char* out1 = result1;
	unsigned char* out2 = result2;
	int out_len = 16;

	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX *ctx2;
	ctx2 = EVP_CIPHER_CTX_new();

	EVP_DecryptInit(ctx, EVP_aes_256_cbc(), dhkey, NULL);
	EVP_DecryptUpdate(ctx, out1, &out_len, dblock1, 16);
	EVP_CIPHER_CTX_free(ctx);

	EVP_DecryptInit(ctx2, EVP_aes_256_cbc(), dhkey, NULL);
	EVP_DecryptUpdate(ctx2, out2, &out_len, dblock2, 16);
	EVP_CIPHER_CTX_free(ctx2);

	unsigned char pkh1[16];
	unsigned char pkh2[16];
	for (int i = 0; i < 16; ++i) {
		pkh1[i] = result1[i] ^ d1h1[i];
		pkh2[i] = result2[i] ^ d1h2[i];
		}

	uint256_t final_priv_key, chunk1, chunk2;
	for (int j = 15; j > -1; --j) {
		chunk1 = pkh1[15 - j];
		chunk2 = pkh2[15 - j];
		chunk1 = chunk1 << ((j + 16) * 8);
		chunk2 = chunk2 << (j * 8);
		final_priv_key += (chunk1 + chunk2);
		}

	// string final_wif_comp = priv_to_wif_comp(final_priv_key);
	// return final_wif_comp;

	return final_priv_key;

	}


int get_ecdsa_sig(unsigned char* t_digest, int t_dlen, unsigned char* t_secret, unsigned char** t_sigpp) {

	const EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
	EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
	EC_POINT* ecpoint = EC_POINT_new(ecgroup);

	BN_CTX* bnctx = BN_CTX_new();
	const BIGNUM* priv_bn = BN_bin2bn(t_secret, 32, NULL);

	EC_POINT_mul(ecgroup, ecpoint, priv_bn, NULL, NULL, bnctx);
	const EC_POINT* pubkey = EC_POINT_dup(ecpoint, ecgroup);
	EC_KEY_set_private_key(eckey, priv_bn);
	EC_KEY_set_public_key(eckey, pubkey);

	const ECDSA_SIG* ecwit = ECDSA_do_sign(t_digest, t_dlen, eckey);
	size_t siglen = i2d_ECDSA_SIG(ecwit, t_sigpp);
	*t_sigpp -= siglen;

	return siglen;

	}


void get_output_serial(string t_address, double t_amount, unsigned char* osout) {
	// output size = 8 + 4 + 20 + 2 = 34.

	unsigned char* rawpub = new unsigned char;

	const string decoder = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	size_t adlen = t_address.length();
	uint256_t bigN, chunk, cbyte;
	int value;
	for (size_t i = 0; i < adlen; ++i) {
		value = decoder.find(t_address[i]);
		chunk = 58;
		chunk = pow(chunk, adlen - 1 - i) * value;
		bigN += chunk;
		}

	unsigned char ibyte;
	for (int j = 0; j < 20; ++j) {
		cbyte = (bigN >> (23 - j) * 8) & 0xFF;
		while (cbyte > 0) {++ibyte; --cbyte;}
		rawpub[j] = ibyte;
		ibyte = 0;
		}

	uint64_t satoshi = t_amount * 100000000;
	unsigned char abyte;
	for (int i = 0; i < 8; ++i) {
		abyte = (satoshi >> (i * 8)) & 0xFF;
		osout[i] = abyte;
		}

	osout[8] = 0x19;
	osout[9] = 0x76;
	osout[10] = 0xa9;
	osout[11] = 0x14;

	for (int i = 0; i < 20; ++i)
	{osout[12 + i] = rawpub[i];}

	osout[32] = 0x88;
	osout[33] = 0xac;

	}


string create_raw_transaction(vector<UTXO>& t_uts, vector<string>& t_wif_set, string t_recip, string t_chg, double t_pay, double t_fee) {

	vector<UTXO> utins;
	size_t allulen = t_uts.size();
	double wealth = 0, gross = t_pay + t_fee;
	for (size_t i = 0; i < allulen; ++i) {
		if (wealth < gross) {
			if (t_uts[i].good()) {
				utins.push_back(t_uts[i]);
				t_uts[i].destroy();
				wealth = wealth + t_uts[i].get_balance();}
			}
		else {break;}
		}

	double change = wealth - t_pay - t_fee;
	unsigned char ninp = (unsigned char)utins.size();
	unsigned char noup = 0x02;

	vector<unsigned char> tx_struct, tx_final;
	tx_struct.push_back(0x01); tx_final.push_back(0x01);
	tx_struct.push_back(0x00); tx_final.push_back(0x00);
	tx_struct.push_back(0x00); tx_final.push_back(0x00);
	tx_struct.push_back(0x00); tx_final.push_back(0x00);
	tx_struct.push_back(ninp); tx_final.push_back(ninp);	// branch off.

	for (size_t i = 0; i < utins.size(); ++i) {
		unsigned char* stc_input = new unsigned char[66];
		utins[i].input_serial(stc_input);
		for (int j = 0; j < 66; ++j)
		{tx_struct.push_back(stc_input[j]);}
		}

	tx_struct.push_back(noup);
	unsigned char* rec_out = new unsigned char[34];
	unsigned char* chg_out = new unsigned char[34];
	get_output_serial(t_recip, t_pay, rec_out);
	get_output_serial(t_chg, change, chg_out);

	for (int i = 0; i < 34; ++i)
	{tx_struct.push_back(rec_out[i]);}
	for (int i = 0; i < 34; ++i)
	{tx_struct.push_back(chg_out[i]);}
	tx_struct.push_back(0x00); tx_struct.push_back(0x00);
	tx_struct.push_back(0x00); tx_struct.push_back(0x00);
	tx_struct.push_back(0x01); tx_struct.push_back(0x00);
	tx_struct.push_back(0x00); tx_struct.push_back(0x00);

	// get signature.
	unsigned char* d1 = new unsigned char[32];
	unsigned char* digest_stc = new unsigned char[32];
	SHA256_CTX shactx;
	SHA256_Init(&shactx);
	for (size_t i = 0; i < tx_struct.size(); ++i)
	{SHA256_Update(&shactx, &tx_struct[i], 1);}
	SHA256_Final(d1, &shactx);
	SHA256_Init(&shactx);
	for (size_t i = 0; i < 32; ++i)
	{SHA256_Update(&shactx, &(d1[i]), 1);}
	SHA256_Final(digest_stc, &shactx);


	unsigned char tm;
	vector<unsigned char> all_sigs;
	vector<int> all_siglens;
	int wlen;
	for (size_t i = 0; i < utins.size(); ++i) {
		unsigned char* so = new unsigned char[1024];
		unsigned char** sigpp = &so;
		unsigned char* isecret = new unsigned char[32];
		utins[i].fetch_private(t_wif_set, isecret);
		wlen = get_ecdsa_sig(digest_stc, 32, isecret, sigpp);
		all_siglens.push_back(wlen);
		for (int j = 0; j < wlen; ++j) {
			tm = (*sigpp)[j];
			all_sigs.push_back(tm);
			}
		}

	// finalize the tx.
	unsigned char publen = 0x21;
	unsigned char ecslen;
	unsigned char sigplen;
	unsigned char fullsiglen;
	int sigmark = 0;
	for (size_t i = 0; i < utins.size(); ++i) {
		unsigned char* bcs = new unsigned char[36];
		utins[i].bc_partial_serial(bcs);
		for (int j = 0; j < 36; ++j)
		{tx_final.push_back(bcs[j]);}

		ecslen = (unsigned char)all_siglens[i];
		sigplen = ecslen + 0x01;
		fullsiglen = ecslen + 0x02 + 0x01 + publen;
		tx_final.push_back(fullsiglen);
		tx_final.push_back(sigplen);
		for (int j = 0; j < ecslen; ++j) {
			tm = all_sigs[j + sigmark];
			tx_final.push_back(tm);
			}
		sigmark += ecslen;
		tx_final.push_back(0x01);

		unsigned char* asecret = new unsigned char[32];
		unsigned char* acs = new unsigned char[38];
		utins[i].fetch_private(t_wif_set, asecret);
		utins[i].ac_partial_serial(asecret, acs);
		for (int j = 0; j < 38; ++j)
		{tx_final.push_back(acs[j]);}
		}

	tx_final.push_back(noup);
	unsigned char* nrec_out = new unsigned char[34];
	unsigned char* nchg_out = new unsigned char[34];
	get_output_serial(t_recip, t_pay, nrec_out);
	get_output_serial(t_chg, change, nchg_out);
	for (int i = 0; i < 34; ++i)
	{tx_final.push_back(nrec_out[i]);}
	for (int i = 0; i < 34; ++i)
	{tx_final.push_back(nchg_out[i]);}
	tx_final.push_back(0x00); tx_final.push_back(0x00);
	tx_final.push_back(0x00); tx_final.push_back(0x00);

	unsigned char* id1 = new unsigned char[32];
	unsigned char* txid = new unsigned char[32];
	SHA256_Init(&shactx);
	for (size_t i = 0; i < tx_final.size(); ++i)
	{SHA256_Update(&shactx, &(tx_final[i]), 1);}
	SHA256_Final(id1, &shactx);
	SHA256_Init(&shactx);
	for (int i = 0; i < 32; ++i)
	{SHA256_Update(&shactx, &(id1[i]), 1);}
	SHA256_Final(txid, &shactx);

	string final_id;
	string hex_table = "0123456789abcdef";
	int big, small;
	for (int i = 31; i >= 0; --i) {
		small = txid[i] % 16;
		big = (txid[i] - small) / 16;
		final_id += hex_table[big];
		final_id += hex_table[small];
		}

	cout << "\n---------- New Transaction ----------\n" << endl;
	cout << "Full TX Data: " << hex;
	for (size_t i = 0; i < tx_final.size(); ++i)
	{cout << setfill('0') << setw(2) << (int)tx_final[i];}
	cout << "     ----- End of Data\n" << endl;
	cout << "Data Size: " << dec << tx_final.size() << " Bytes" << endl;
	cout << "New TXID: " << final_id << endl;
	cout << "Change Paid Back: " << change << " BTC" << endl;
	cout << "Adding Outputs to UTXO Set......";
	t_uts.push_back(UTXO(final_id, t_recip, "NO", 0, t_pay));
	t_uts.push_back(UTXO(final_id, t_chg, "NO", 1, change));
	cout << " Finished.\n" << endl;
	cout << "---------- Operation Complete ----------\n" << endl;

	return final_id;

	}
