/* btcStructs.cxx */
/* ====================================================================
 * INCLUDE ALL BITCOIN RELATED CLASSES FOR THIS PROJECT.
 * DO NOT USE DIRECTLY; ONLY USE BY INCLUDING.
 * ====================================================================
 *
 * CLASSES EXPLAINED:
 *
 * #1 UTXO:
 *    A UTXO object will store all information about an Unspent Transaction
 *    Output which can be used as an input(source of funds) for a new
 *    transaction. The class has various member functions to automatically
 *    generate serialized data parts related to inputs inside the raw
 *    transaction data recorded on the Blockchain.
 *
 * #
 *
 *
 */

#include "btcStructs.h"
#include "btcTools.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <cmath>

using namespace std;
using namespace boost::multiprecision;

typedef vector<unsigned char>::iterator vbit;


UTXO::UTXO(string id, string add, string sp, int ix, double amt) {

	txid = id;
	address = add;
	spendable = sp;
	index = ix;
	amount = amt * 100000000;

	}


bool UTXO::good() {

	if (spendable == "YES")
	{return true;}
	else {return false;}

	}


double UTXO::get_balance() {

	double balance = amount;
	balance = balance / 100000000;
	return balance;

	}


void UTXO::print_info() {

	cout << "\nTXID: " << txid << "\nIndex: " << index;
	cout << "\nPay to Address: " << address;
	cout << "\nAmount: " << amount << " Satoshis";
	cout << "\nSpendable: " << spendable << "\n" << endl;

	}


void UTXO::export_to_file(ofstream& t_ufile) {

	t_ufile << txid << " " << address << " " << spendable << " ";
	double dmt = amount;
	dmt /= 100000000;
	t_ufile << index << " " << dmt << "\n";

	}


void UTXO::pkhash_decode(unsigned char* pkhout) {

	const string decoder = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	size_t adlen = address.length();
	uint256_t bigN, chunk, cbyte;
	int value;
	for (size_t i = 0; i < adlen; ++i) {
		value = decoder.find(address[i]);
		chunk = 58;
		chunk = pow(chunk, adlen - 1 - i) * value;
		bigN += chunk;
		}

	unsigned char ibyte;
	for (int j = 0; j < 20; ++j) {
		cbyte = (bigN >> (23 - j) * 8) & 0xFF;
		while (cbyte > 0) {++ibyte; --cbyte;}
		pkhout[j] = ibyte;
		ibyte = 0;
		}

	}


void UTXO::fetch_private(vector<string>& t_wif_set, unsigned char* keyout) {

	uint256_t real_key, chunk;

	for (vector<string>::iterator si = t_wif_set.begin(); si != t_wif_set.end(); ++si) {
		if (wif_comp_to_pkh(*si) == address) {
			real_key = wif_to_priv(*si);
			break;
			}
		}

	unsigned char ibyte;
	for (int i = 0; i < 32; ++i) {
		chunk = (real_key >> ((31 - i) * 8)) & 0xFF;
		while (chunk > 0) {++ibyte; --chunk;}
		keyout[i] = ibyte;
		ibyte = 0;
		}

	}


void UTXO::bc_partial_serial(unsigned char* icout) {
	// partial size = 32 + 4 = 36.

	uint64_t id1, id2, id3, id4;
	string ids1 = txid.substr(0, 16);
	string ids2 = txid.substr(16, 16);
	string ids3 = txid.substr(32, 16);
	string ids4 = txid.substr(48, 16);
	stringstream(ids1) >> hex >> id1;
	stringstream(ids2) >> hex >> id2;
	stringstream(ids3) >> hex >> id3;
	stringstream(ids4) >> hex >> id4;
	for (int i = 0; i < 8; ++i) {
		icout[i] = (id4 >> i * 8) & 0xFF;
		icout[i + 8] = (id3 >> i * 8) & 0xFF;
		icout[i + 16] = (id2 >> i * 8) & 0xFF;
		icout[i + 24] = (id1 >> i * 8) & 0xFF;
		}

	uint64_t ix = index;
	for (int i = 0; i < 4; ++i) {icout[i + 32] = (ix >> i * 8) & 0xFF;}

	}


void UTXO::ac_partial_serial(unsigned char* t_secret, unsigned char* acout) {
	// partial size = 1 + 33(1 + 32) + 4 = 38.

	unsigned char* pubkey = new unsigned char[33];

	EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
	EC_POINT* ecpoint = EC_POINT_new(ecgroup);
	BN_CTX* bnctx = BN_CTX_new();
	BIGNUM* priv_bn = BN_bin2bn(t_secret, 32, NULL);
	EC_POINT_mul(ecgroup, ecpoint, priv_bn, NULL, NULL, bnctx);
	EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_COMPRESSED,
					   pubkey, 33, bnctx);

	acout[0] = 0x21;
	for (int i = 0; i < 33; ++i)
	{acout[1 + i] = pubkey[i];}
	acout[34] = 0xFF;
	acout[35] = 0xFF;
	acout[36] = 0xFF;
	acout[37] = 0xFF;

	}


void UTXO::input_serial(unsigned char* sout) {
	// input size = 32 + 4 + 1 + 25 + 4 = 66.

	uint64_t id1, id2, id3, id4;
	string ids1 = txid.substr(0, 16);
	string ids2 = txid.substr(16, 16);
	string ids3 = txid.substr(32, 16);
	string ids4 = txid.substr(48, 16);
	stringstream(ids1) >> hex >> id1;
	stringstream(ids2) >> hex >> id2;
	stringstream(ids3) >> hex >> id3;
	stringstream(ids4) >> hex >> id4;
	for (int i = 0; i < 8; ++i) {
		sout[i] = (id4 >> i * 8) & 0xFF;
		sout[i + 8] = (id3 >> i * 8) & 0xFF;
		sout[i + 16] = (id2 >> i * 8) & 0xFF;
		sout[i + 24] = (id1 >> i * 8) & 0xFF;
		}

	uint64_t ix = index;
	for (int i = 0; i < 4; ++i) {sout[i + 32] = (ix >> i * 8) & 0xFF;}

	sout[36] = 0x19;
	sout[37] = 0x76;
	sout[38] = 0xa9;
	sout[39] = 0x14;
	unsigned char* pkh = new unsigned char[20];
	this->pkhash_decode(pkh);
	for (int i = 0; i < 20; ++i) {sout[i + 40] = pkh[i];}

	sout[60] = 0x88;
	sout[61] = 0xac;
	sout[62] = 0xff;
	sout[63] = 0xff;
	sout[64] = 0xff;
	sout[65] = 0xff;

	}
