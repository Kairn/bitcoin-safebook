/* btcTools.h */

#ifndef BTCTOOLS_H
#define BTCTOOLS_H

#include <boost/multiprecision/cpp_int.hpp>
#include <string>

boost::multiprecision::uint256_t urandom_256();

std::string priv_to_wif_comp(boost::multiprecision::uint256_t t_raw_key);

boost::multiprecision::uint256_t wif_to_priv(std::string t_wif_key);

std::string wif_comp_to_pkh(std::string t_wif_comp);

std::string wif_comp_to_cipher6p(std::string t_wif_comp, std::string t_password);

boost::multiprecision::uint256_t cipher6p_decrypt(std::string t_cipher6p, std::string t_password);

int get_ecdsa_sig(unsigned char*, int, unsigned char*, unsigned char**);

void get_output_serial(std::string, double, unsigned char*);

std::string create_raw_transaction(std::vector<UTXO>&, std::vector<std::string>&, std::string, std::string, double, double);

#endif
