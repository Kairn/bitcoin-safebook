/* Initialize_Wallet.cxx */
/* ====================================================================
 * SOURCE FILE FOR THE WALLET INITIALIZATION PROCESS.
 *
 * !!! WARNINGS !!! PLEASE READ !!!
 *
 * EXECUTION OF THIS SCRIPT WILL COMPLETELY WIPE OUT THE CURRENT WALLET
 * DATA! ONLY USE THIS TO CREATE A NEW WALLET! MAKE SURE TO BACK UP ALL
 * WALLET FILES IN THE CASE OF ACCIDENTAL MISUSE. YOU WILL PERMANENTLY
 * LOSE YOUR BITCOIN IF YOU LOSE THE WALLET FILES WHICH CONTAIN THE
 * ADDRESS(ES) TO WHICH YOU SEND REAL BITCOIN.
 *
 * A STRONG PASSWORD FOR THE WALLET IS ABSOLUTELY CRITICAL, BUT YOU HAVE
 * TO REMEMBER THE PASSWORD VERBATIM OR YOU WILL LOSE ALL FUNDS THAT
 * BELONG TO THE WALLET.
 * ====================================================================
 *
 * BUILD COMMAND: g++ -Wall -o initSafeBook Initialize_Wallet.cxx btcTools.cxx btcStructs.cxx -lcrypto -lssl
 * RUN COMMAND: ./initSafeBook
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


int main() {

	cout << "\n========== SAFEBOOK INITIALIZATION ==========\n" << endl;
	cout << "***WARNING***" << endl;
	cout << "MAKE SURE YOUR MACHINE IS DISCONNECTED." << endl;
	cout << "THIS PROCESS WILL WIPE ALL OLD DATA." << endl;
	cout << "PLEASE BACK UP FILES ACCORDINGLY IF YOU ARE RESETTING THE WALLET.\n" << endl;

	cout << "Are you sure to continue?(Y/N)" << endl;
	char init;
	cin >> init;
	if (init == 'Y' or init == 'y') {

		cout << "\nInitializating......\n" << endl;
		char wsize;
		int ksize;
		cout << "Please choose your wallet size and press Enter:" << endl;
		cout << "S(100 keys)/M(500 keys)/L(1000 keys)" << endl;
		cin >> wsize;
		while (true) {
			if (wsize == 'S' or wsize == 's')
			{ksize = 100; break;}
			else if (wsize == 'M' or wsize == 'm')
			{ksize = 500; break;}
			else if (wsize == 'L' or wsize == 'l')
			{ksize = 1000; break;}
			else {cout << "Please enter S or M or L." << endl;
				  cin >> wsize;}
		}

		cout << "\nKey generation process starting......\n" << endl;
		cout << "You need to provide a password for key encryption.\n" << endl;
		cout << "***WARNING***" << endl;
		cout << "YOU MUST REMEMBER THE PASSWORD VERBATIM OR YOUR KEYS WILL BE LOST FOREVER!\n" << endl;
		string password, pw2;
		while (true) {
			cout << "Enter your password:" << endl;
			cin >> password;
			cout << "Re-type your password to confirm:" << endl;
			cin >> pw2;
			if (password == pw2)
			{break;}
			else {cout << "The passwords do not match, try again.\n" << endl;}
		}

		cout << "\nPassword successfully set up.\n" << endl;
		cout << "Now generating keys......" << endl;
		vector<string> pkh_set, cp6_set;
		string twif, tpkh, tcp6;
		for (int i = 0; i < ksize; ++i) {
			twif = priv_to_wif_comp(urandom_256());
			tpkh = wif_comp_to_pkh(twif);
			tcp6 = wif_comp_to_cipher6p(twif, password);
			pkh_set.push_back(tpkh);
			cp6_set.push_back(tcp6);
			}
		cout << "Finished generating " << ksize << " keys.\n" << endl;

		cout << "Now writing to files......" << endl;
		ofstream addressFile("wallet_data/Addresses.txt");
		ofstream cp6File("wallet_data/Cipher_Keys.txt");
		ofstream utxoFile("wallet_data/UTXOs.txt");
		string nline = "\n";
		if (addressFile) {
			for (int i = 0; i < ksize; ++i)
			{addressFile << pkh_set[i] << nline;}
			}
		if (cp6File) {
			for (int i = 0; i < ksize; ++i)
			{cp6File << cp6_set[i] << nline;}
			}
		if (utxoFile) {
			string sampleID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
			string sampleADD = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
			UTXO* sample = new UTXO(sampleID, sampleADD, "NO", 0, 50);
			sample->export_to_file(utxoFile);
			}
		addressFile.close();
		cp6File.close();
		utxoFile.close();
		cout << "Done." << endl;
		cout << "Terminating process......\n" << endl;

	}

	if (init == 'Y' or init == 'y')
	{cout << "INITIALIZATION COMPLETE. PLEASE BACK UP FILES ASAP!\n" << endl;}
	else {cout << "Process terminated by the user.\n" << endl;}

	return 0;

}
