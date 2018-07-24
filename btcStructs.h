/* btcStructs.h */

#ifndef BTCSTRUCTS_H
#define BTCSTRUCTS_H

#include <vector>
#include <string>
#include <fstream>
#include <iostream>

class UTXO {
	
	private:
		std::string txid, address, spendable;
		int index;
		long amount;
	
	public:
		UTXO(std::string, std::string, std::string, int, double);
		bool good();
		double get_balance();
		void print_info();
		void export_to_file(std::ofstream&);
		void pkhash_decode(unsigned char*);
		void fetch_private(std::vector<std::string>&, unsigned char*);
		void input_serial(unsigned char*);
		void bc_partial_serial(unsigned char*);
		void ac_partial_serial(unsigned char*, unsigned char*);
		void destroy() {spendable = "NO";}
		void activate() {spendable = "YES";}
		
};

#endif
