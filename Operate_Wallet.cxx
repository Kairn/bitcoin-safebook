/* Operate_Wallet.cxx */
/* ====================================================================
 * SOURCE FILE FOR LAUNCHING THE WALLET PROGRAM(AFTER INITIALIZATION).
 *
 * !!! WARNINGS !!! PLEASE READ !!!
 *
 * MAKE SURE YOU FIRST INITIALIZE THE WALLET OR THE PROGRAM MIGHT FAIL.
 *
 * A PASSWORD IS REQUIRED IN ORDER TO USE THE WALLET, BUT THE PROGRAM
 * WILL NOT INFORM THE USER WHETHER THE PASSWORD IS CORRECT OR NOT. THIS
 * IS DONE TO PREVENT A BRUTE FORCE ATTACK. IF YOU DO NOT HAVE A VALID
 * PASSWORD, THE TRANSACTIONS CREATED WILL BE INVALID AND THEREFORE NEVER
 * MINED BY BITCOIN NETWORK PEERS.
 * ====================================================================
 *
 * BUILD COMMAND: g++ -Wall -o runSafeBook Operate_Wallet.cxx btcTools.cxx btcStructs.cxx -lcrypto -lssl
 * RUN COMMAND: ./runSafeBook
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
#include <cstdlib>
#include <ctime>
#include <limits>

using namespace std;
using namespace boost::multiprecision;

typedef vector<unsigned char>::iterator vbit;


int simple_rng(size_t maxv) {
	// A simple random number generator.

	int rnum;
	srand(time(NULL));
	rnum = rand() % maxv;
	return rnum;

	}


double wallet_balance(vector<UTXO>& t_utxo_set) {
	// calculate the current balance of the wallet.

	double balance;
	for (size_t i = 0; i < t_utxo_set.size(); ++i) {
		if (t_utxo_set[i].good())
		{balance += t_utxo_set[i].get_balance();}
		}
	if (balance < 0.00000001) {balance = 0;}
	return balance;

	}


void display_help() {
	// display command options.

	cout << "\n----- Command Options -----\n" << endl;
	cout << "-h     display help" << endl;
	cout << "-r     get a receive address" << endl;
	cout << "-b     display your current balance" << endl;
	cout << "-u     load a new UTXO into the wallet" << endl;
	cout << "-s     send Bitcoin to another address" << endl;
	cout << "-q     end the session and quit" << endl;
	cout << "\n----- END -----\n" << endl;

	}


void get_address(vector<string>& t_addr_set) {
	// return a randomly chosen Bitcoin address from the wallet.

	string address;
	size_t ksize = t_addr_set.size();
	address = t_addr_set[simple_rng(ksize)];
	cout << "\nReceive address: " << address  << "\n" << endl;

	}


string get_address_c(vector<string>& t_addr_set) {
	// for internal function use.

	string address;
	size_t ksize = t_addr_set.size();
	address = t_addr_set[simple_rng(ksize)];
	cout << "Change address: " << address << endl;
	return address;

	}


void new_utxo(vector<UTXO>& t_utxo_set) {
	// add a new UTXO to the set after your wallet is paid Bitcoin.

	char cf;
	string id, addr;
	int ix;
	double amt;
	cout << "\nEnter the transaction ID: " << endl;
	cin >> id;
	cout << "Enter the output index: " << endl;
	cin >> ix;
	while (cin.fail()) {
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(),'\n');
    cout << "invalid entry. Enter a numeric:" << endl;
    cin >> ix;
	}
	cout << "Enter the receiving address (from your current wallet only!): " << endl;
	cin >> addr;
	cout << "Enter the amount in BTC: " << endl;
	cin >> amt;
	while (cin.fail()) {
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(),'\n');
    cout << "invalid entry. Enter a numeric:" << endl;
    cin >> amt;
	}

	cout << "\nAre your sure the information is correct and ";
	cout << "want to continue?(Y/N)?" << endl;
	cin >> cf;

	if (cf == 'Y' or cf == 'y')
	{t_utxo_set.push_back(UTXO(id, addr, "YES", ix, amt));
	cout << "\nCompleted.\n" << endl;}
	else {cout << "Aborted.\n" << endl;}

	}


void new_transaction(vector<UTXO>& t_utxo_set, vector<string>& t_wif_set, vector<string>& t_addr_set) {
	// generate the raw byte data for a new transaction for sending Bitcoin.

	char cg, cf;
	string radd, cadd;
	double txpay, txfee;

	cout << "\nEnter the recipient's address: " << endl;
	cin >> radd;
	cout << "Use a random change address?(Y/N)?" << endl;
	cin >> cg;
	if (cg == 'Y' or cg == 'y')
	{cadd = get_address_c(t_addr_set);}
	else {cout << "Enter the change address: " << endl; cin >> cadd;}
	cout << "Enter the amount you wish to send in BTC: " << endl;
	cin >> txpay;
	while (cin.fail()) {
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(),'\n');
    cout << "invalid entry. Enter a numeric:" << endl;
    cin >> txpay;
	}
	cout << "Enter the transaction fee in BTC: " << endl;
	cin >> txfee;
	while (cin.fail()) {
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(),'\n');
    cout << "invalid entry. Enter a numeric:" << endl;
    cin >> txfee;
	}

	cout << "\nAre you sure the information is correct and ";
	cout << "want to continue?(Y/N)?" << endl;
	cin >> cf;

	if (cf == 'Y' or cf == 'y') {
		if (wallet_balance(t_utxo_set) > (txpay + txfee)) {
			cout << "\nOK, processing your request......\n" << endl;
			create_raw_transaction(t_utxo_set, t_wif_set, radd, cadd, txpay, txfee);
			cout << "\nWould you like to register the change as a new UTXO?(Y/N)" << endl;
			cin >> cg;
			if (cg == 'Y' or cg == 'y') {
				t_utxo_set[t_utxo_set.size() - 1].activate();
				cout << "\nOutput loaded and activated.\n" << endl;
				}
			else {cout << "\nYou can add this UTXO later after network confirmation.\n" << endl;}
			}
		else {cout << "\nCan't proceed due to insufficient balance.\n" << endl;}
		}
	else {cout << "Aborted.\n" << endl;}
	}


int main() {

	cout << "\n========== SAFEBOOK OFFLINE OPERATION ==========\n" << endl;
	cout << "***WARNING***" << endl;
	cout << "MAKE SURE YOUR MACHINE IS DISCONNECTED.\n" << endl;

	ifstream pkhFile("wallet_data/Addresses.txt");
	ifstream cp6File("wallet_data/Cipher_Keys.txt");
	ifstream utxoFile("wallet_data/UTXOs.txt");

	if (pkhFile.good() and cp6File.good() and utxoFile.good()) {

		// load UTXOs and back up the data.
		cout << "Backing up UTXOs file......" << endl;
		vector<UTXO> utxo_set;
		string a, b, c, dd, ee;
		int d; double e;
		while (utxoFile >> a >> b >> c >> dd >> ee) {
			stringstream(dd) >> d;
			stringstream(ee) >> e;
			utxo_set.push_back(UTXO(a, b, c, d, e));
			}
		ofstream utxoBack("wallet_data/UTXOs.txt.bak");
		if (utxoBack) {
			for (size_t i = 0; i < utxo_set.size(); ++i)
			{utxo_set[i].export_to_file(utxoBack);}
			}
		utxoBack.close();
		utxoFile.close();
		cout << "Done.\n" << endl;

		// load wallet data and decrypt keys.
		string pw, tm;
		cout << "Please enter your password: " << endl;
		cin >> pw;
		cout << "\nOK, decrypting keys......" << endl;
		vector<string> addr_set, wif_set;
		while (pkhFile >> tm)
		{addr_set.push_back(tm);}
		while (cp6File >> tm) {
			tm = priv_to_wif_comp(cipher6p_decrypt(tm, pw));
			wif_set.push_back(tm);
			}
		pkhFile.close();
		cp6File.close();
		cout << "Done.\n" << endl;

		cout << "Your wallet is now ready for use." << endl;
		cout << "Your current balance: " << wallet_balance(utxo_set) << " BTC\n" << endl;

		// main operation loop for the application.
		cout << "Enter a user command to perform action. Enter -h for help." << endl;
		string cmd;
		while (true) {

			cout << "$ ";
			cin >> cmd;

			if (cmd == "-h")
			{display_help();}
			else if (cmd == "-r")
			{get_address(addr_set);}
			else if (cmd == "-b")
			{cout << "\nYour current balance: " << wallet_balance(utxo_set) << " BTC\n" << endl;}
			else if (cmd == "-u")
			{new_utxo(utxo_set);}
			else if (cmd == "-s")
			{new_transaction(utxo_set, wif_set, addr_set);}
			else if (cmd == "-q")
			{break;}
			else {cout << "\nInvalid command.\n" << endl;}

		}

		// export the new UTXO data and exit.
		ofstream utxoEx("wallet_data/UTXOs.txt");
		cout << "\nRefreshing UTXO list......" << endl;
		if (utxoEx) {
			for (size_t i = 0; i < utxo_set.size(); ++i)
			{utxo_set[i].export_to_file(utxoEx);}
			}
		utxoEx.close();
		cout << "Done." << endl;
		cout << "\nSession ended successfully.\n" << endl;

	}
	else {cout << "No wallet data found. Please initialize first.\n" << endl;}

	return 0;

}
