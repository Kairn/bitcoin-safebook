# Bitcoin SafeBook - Alpha Version
[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.png?v=103)](https://github.com/ellerbrock/open-source-badges/)
[![made-with-cpp](https://img.shields.io/badge/made%20with-C%2B%2B-yellowgreen.svg)](https://isocpp.org)
[![MIT Licence](https://img.shields.io/apm/l/vim-mode.svg)](https://opensource.org/licenses/mit-license.php)

Bitcoin SafeBook (or SafeBook) is an experimental project with a goal to design a simple application that allows anyone to store and spend Bitcoin safely.

****WARNING: The current version of this program has not been thoroughly tested with real Bitcoin. Use at your own risk. Try it with tiny payments first before attempting to store considerable amounts of Bitcoin.***

## About Bitcoin

### The Network
Bitcoin is the name of an experimental digital currency system/platform that allows anonymous payments to be made to any anonymous entity/person/group worldwide via a peer-to-peer network. Bitcoin uses a variety of cryptographic algorithms to secure the owner's assets, ensure the integrity of digital transactions, and prevent double spending. Bitcoin utilizes a publicly distributed ledger called the Blockchain to record every legitimate transaction ever occurred during the entire lifetime of the network since its creation in 2009. Every node of the Bitcoin network that wishes to participate can download the whole Blockchain from its peers, but it will validate all blocks and transactions independently thus eliminating the need for a trusted third party to distribute the "Real" Blockchain.

### The Currency
Bitcoin also refers to the underlying digital currency used in the Bitcoin network. This currency is technically denominated in satoshi (named after Satoshi Nakamoto, the creator of Bitcoin) which is the smallest unit that can be transacted in the network. One Bitcoin (BTC) is worth one hundred million satoshi. New Bitcoin is only generated through Mining - the process by which transactions are recorded on the Blockchain. The network consensus rules allow the dynamic adjustment of mining difficulty in order to make the supply of new Bitcoin predictable in the long term. On average, a new block is mined every 10 minutes with its block reward credited to the miner for his contribution to the network. The block reward is initially 50 Bitcoin, and it is set to be halved for about every 4 years. The last Bitcoin is predicted to be mined in the year 2140 after which miners will only get transaction fees as compensation.

*for more information, please visit [bitcoin.org](https://bitcoin.org/en/)*

## What is a Bitcoin Wallet?

### Full Service Networked Wallet
Most of the Bitcoin Wallets are software programs that can be downloaded and installed on a desktop computer or a mobile device. A such typical program will manage a collection of private keys which allow the spending of Bitcoin previously paid to their corresponding addresses, actively scan the network for newly received Bitcoin, and send Bitcoin to new owners upon the user's request. Full service wallets are easy to use and usually free of charge, and they are popular amongst newer Bitcoin users. But the convenience of these wallets do come at a cost regarding security. Since a full service wallet needs Internet connection to fully function, it is vulnerable to malicious attacks if there are security loopholes in its implementation or the underlying OS. A poorly built wallet can put the user's privacy at risk and may even lead to the user's Bitcoin being stolen. Storing large amounts of Bitcoin in a fully networked wallet is strongly discouraged by the community.

### Offline Wallet
In order to eliminate the security risks that come with a fully networked wallet, more sophisticated Bitcoin users utilize offline wallets, sometimes called cold storage, to keep their private key information away from the unsafe Internet. Offline wallets exist in many different forms depending on the functionalities. An offline wallet can be as simple as a piece of paper that has the user's key pairs written on it in plaintext, or it could be a complex piece of hardware that not only secures the user's key information with advanced encryption methods but is also able to digitally sign transactions of various types. Some high end hardware wallets can also communicate with the Bitcoin network through dedicated online applications so that the users can promptly send and receive payments. Due to the fact that a hardware wallet does not rely on a general purpose OS like a regular desktop application, the risk of it being the victim of a malicious attack is minimal as long as the user properly follows the instructions given by the wallet's manufacturer.

## About SafeBook

### Security
SafeBook is designed to operate in an offline environment. The lack of networking makes the program immune to remote hacking if the host machine stays disconnected permanently. Moreover, the user's key information, which is saved on a local disk, will be encrypted by SafeBook using a method similar to the standardized algorithm specified in BIP-38. This ensures that the user's private keys are safe from others who may share the same machine. Lastly, although not necessarily recommended, it is not seriously dangerous to connect the host machine to the Internet when the program is not running since the wallet files alone are not useful to anyone without the correct password. However, the risk of the user's password being captured and leaked by some malware does increase considerably if the machine regularly goes online.

### Disadvantages
SafeBook only runs in a terminal, and the lack of GUI means it is less user friendly. Secondly, SafeBook only supports regular Bitcoin addresses (the ones begin with "1"), and it cannot create transactions that involve more complex types of payments such as Pay to Script Hash. Besides these inconveniences, SafeBook is very self unaware of the integrity of the data it processes. For example, a typical password protected hardware wallet will refuse to do decryption and issue a warning if the user has entered a wrong password, but SafeBook will happily accept any valid string as password and run the decryption algorithm without knowing whether the password is correct or not. An incorrect password will yield invalid transactions if the user tries to spend any Bitcoin, so this does not compromise security, but it can cause minor trouble to a legitimate user who might make honest mistakes. In fact, SafeBook does not perform any check on the data either from the user's direct inputs or inside the wallet files. When mistakes/accidents occur, it is possible for the program to fail and cause data corruption, and therefore keeping a backup of all wallet files is an absolute necessity when using SafeBook. Luckily, as long as the password is not leaked and the user has not lost his backup, virtually nothing can lead to the loss/theft of Bitcoin.

## Using SafeBook

### Prerequisites
* A Linux based operating system ([Ubuntu](https://www.ubuntu.com/download/alternative-downloads) recommended, not tested with other distributions)
* [OpenSSL](https://www.openssl.org/source/)
* [Boost](https://www.boost.org/)
* [GNU Compiler Collection](https://gcc.gnu.org/)

### Install and Run
1. Download the repository as a .zip file or using git clone.
2. Extract the .zip file.
3. Open a terminal and move to the program directory.
4. Run the following command to build the executables from source code:  
	`make all`

5. Use the following commands to launch the program:  
	`./initSafeBook` - initialize the wallet  
	`./runSafeBook` - start the application

### Compatibility
*SafeBook is NOT compatible with any other software or hardware wallets. Do not try to import or export wallet files between different wallets unless you know EXACTLY what you are doing and are willing to bare the responsibility if things go wrong.*

## User Instructions
*Imagine the following scenario: Alice wants to shop at a store owned by Charles who only accepts Bitcoin payments, but Alice has no Bitcoin, so she calls her friend Bob to send her some Bitcoin. I will elaborate on this hypothetical case by detailing exactly how Alice can complete the shopping using SafeBook.*

### Step 1: Receive Bitcoin
In order to receive Bitcoin from Bob, Alice needs to have an address for Bob to send his Bitcoin to. SafeBook will automatically generate a list of Bitcoin addresses during its initialization process which can be started by running "initSafeBook". Alice will then choose a wallet size which determines the number of addresses to be included in the wallet and set a password which she has to keep secret from everyone else. If it all goes fine, the initialization should finish in no time, and Alice will see three new files being created in the subdirectory called "wallet_data". Alice could obtain an address by browsing the files directly, but a better way is for her to use SafeBook's interface. By executing "runSafeBook", Alice will have easy and safe access to the wallet data after she enters the password set previously. Using the command "-r", the program will return an address randomly chosen from the address list. Alice can simply copy the address and send it to Bob who will be able to sent Bitcoin to Alice right after.

### Step 2: Confirm the Receipt
After Bob has broadcast the transaction that pays Alice to the network, it will take on average about an hour for the transaction to be confirmed and safely recorded on the Blockchain. Alice can view the confirmed transaction on [Block Explorer](https://blockexplorer.com/), and in order to tell SafeBook about the receipt, she has to write down (or copy) the transaction ID (a 64-character long string of hex digits), the output index (an integer pointing to the payment to Alice), and the amount received in BTC. She will then launch SafeBook and issue the command "-u" to signal to the program that she has received new Bitcoin. SafeBook will then prompt her to enter the transaction ID, the output index, the receiving address (the one she gave to Bob), and the amount received. After Alice confirms the information, SafeBook will register it as a UTXO which belongs to Alice's wallet and can later be spent by her. If she enters the command "-b", she should see her balance has increased by the amount she received from Bob.

**Block Explorer will not show the output index directly, but it can be easily deduced by locating the position of Alice's address on the output section. The first address will have index 0, and the next will have index 1, and so on. For example, for [this transaction](https://blockexplorer.com/tx/083af7218752af195a6dc872bcd150a506e83d1371dc6881ce0b4050fb3595df), address **"1CWHB2Ac8TLgkNGQ5zbnYKtRHXuUDSVtkE"** has the output index 0, and address **"1MTwWFTWwKPdp9twhW9n3WgXttv8kTfhpq"** has the output index 2. Output index 0 is the most common for recipients of simple transactions.*

### Step 3: Pay with Bitcoin
Now that Alice owns Bitcoin, she can spend it in Charles' store for goods or services. If Alice wants to make a purchase, she will request a Bitcoin address from Charles. Then, she will launch SafeBook and enter the command "-s" to create a paying transaction. SafeBook will then prompt Alice to enter the address of the recipient (Charles), a change address (paying any Bitcoin left over back to Alice), the amount she wishes to pay, and the transaction fee. After Alice confirms the information, SafeBook will use the previously registered UTXO(s) to construct a new raw transaction or reject the request if the wallet has insufficient balance for the payment.

### Step 4: Broadcast the Transaction
After SafeBook has processed a sending request, it will display the transaction data in raw hex format in the terminal. Alice will need to transport this data to a machine with Internet access and broadcast the data with [Block Explorer Send](https://blockexplorer.com/tx/send). If everything goes fine, Charles should get a confirmation shortly after, and Alice has successfully completed her shopping. Finally, SafeBook will ask Alice whether to register the change as a new UTXO immediately after displaying the transaction data. Although it is safer to do this after the network confirmation, if Alice wants to save some time or spend the change right away, she could tell SafeBook to record this information automatically.

### *Tips and Warnings*
1. "initSafeBook" shall only be run when creating a new wallet, or your current wallet data will be wiped out if you choose to continue the process. You can delete this file after initialization to avoid misuse.

2. In order to prevent accidental data corruption, SafeBook will backup the UTXO file when the program is being launched, but the user has to back up the key and address files onto another safe storage (e.g. a flash drive) himself. It is advisable to manually back up the UTXO file as well in between uses.

3. Use the command "-h" to have the program display all command options.

4. SafeBook does not implement the automatic calculation of transaction fees due to the variability of Bitcoin demand and currency exchange rates. See [Bitcoin Fees](https://bitcoinfees.earn.com/#fees) for more information.

5. When sending Bitcoin, the user is advised to use a random change address from the wallet. If the user wants to register the change as a new UTXO immediately, he has to understand the risk involved particularly regarding [transaction malleability](https://en.bitcoin.it/wiki/Transaction_malleability).

## Q&A
1. ***What if I forget the password to the wallet?***
* Answer: You can no longer decrypt the private keys which means any Bitcoin that belongs to the wallet is permanently lost.

2. ***What if my transaction is not recorded on the Blockchain after an hour?***
* Answer: Transactions could take longer to be confirmed depending on the fee. If you've waited long enough and nothing happens, then maybe you have entered a wrong password or other invalid data. Don't panic, you will not lose Bitcoin even if you broadcast an invalid transaction.

3. ***What if my wallet files become corrupted or get lost by accident?***
* Answer: You can directly copy your backup files into the "wallet_data" subdirectory, and then your wallet should be restored. You may need to register some of the UTXOs again if your backup file is outdated.

4. ***What if I registered an invalid UTXO?***
* Answer: If you realized the problem right away, close down the program and replace the current UTXO file with the automatically generated backup file. If you only found out on a later date, you can use your own backup file dated before the mistake and re-register other UTXOs that are still valid. Alternatively, you can open the UTXO file and delete the line with the wrong information, but be very careful if you decide to do this.

5. ***What if the program has crashed?***
* Answer: The current version of SafeBook can have unexpected behaviors if it encounters invalid data. The best cure is prevention, meaning that the user should double check his data inputs and not temper with the wallet files. Having adequate backups is a must. You can also report the issue to me with detailed explanation so I can offer some help.

## Bitcoin Glossary
* **Private Key** - a *unique* 256-bit number. Private keys are generated by SafeBook using cryptographically secure random number generator.
* **Encrypted Key** - a cipher string that can be converted into a private key using the algorithm and the password. You can view them directly in the "Cipher_Keys" file.
* **Public Key** - a *unique* point on the specified elliptical curve which corresponds to a private key. These keys are not visible to the user and are only processed by the program internally.
* **Bitcoin Address** - the hash of a public key encoded in base58 check encoding. Regular addresses always begin with a "1", and SafeBook can only handle this type of addresses. You can view them in the "Addresses" file.
* **Transaction** - a piece of data that specifies the transfer of ownership of Bitcoin. Transactions are signed using the sender's private key(s). *(Only simple P2PKH payments can be created using SafeBook.)*
* **P2PKH** - short for pay to public key hash. It is the de facto payment standard when sending Bitcoin to a regular Bitcoin address.
* **Transaction ID** - the double SHA-256 hash of a transaction data in reverse byte order.
* **Transaction Inputs** - the portion of a transaction that details the source(s) of Bitcoin including the signatures.
* **Transaction Outputs** - the portion of a transaction that details the recipient(s) of Bitcoin with the amount(s) paid to each.
* **UTXO** - an unspent transaction output. Basically, a UTXO details the information of a newly (not spent) received Bitcoin, and this information is necessary in order to construct a transaction input. You can view them in the "UTXOs" file.
* **Transaction Fee** - the difference between the cumulative values of transaction inputs and outputs. Fees are paid to incentivize miners to prioritize transactions.
* **Balance** - the cumulative amount of Bitcoin in all UTXOs recognized by a Bitcoin wallet. This concept only exists in the context of using a specific wallet. The Blockchain has no idea what each wallet contains.

## Final Words
I am an independent developer. I do not necessarily advocate the use of Bitcoin, nor am I affiliated with any organization that provide digital currency services. I will strongly encourage any potential Bitcoin user to do some deep and independent research. SafeBook is currently not a newbie friendly tool, and if you are interested in owning large amounts of Bitcoin, buying a hardware wallet from a trusted company is still a better option.
