Group: Azan Nazar
email: anazar1@binghamton.edu
Language used: C++

- The code was tested on the remote machines and the professor said to 
talk with her regarding the issue of openSSL where she personally recommended to
put example cases showcasing encryptRSA, decryptRSA, signMessage, verifySignature.
(Extra information shown below)



HOW TO RUN  ('>>' is used to indicate terminal):

- For the make and clean command, MAKE sure to be in directory finalp-anazar/ 


- DO NOT RUN "make" or "make clean" INSIDE client/, server/, bank/ or testing/


- testing/ is recommended by Professor Yang due to the errors with openSSL and simply
test


- Recommended to run 3 terminals as the same time where the the active directory
should have either client/, server/, bank/ or testing/ at the end like the following:
     - anazar1@remote06:~/cs558/finalp-anazar/bank$
     - anazar1@remote06:~/cs558/finalp-anazar/server$
     - anazar1@remote06:~/cs558/finalp-anazar/client$


- The manually generated Prb.key, Prs.key, Pub.pem and Pus.pem files are within 
    - anazar1@remote06:~/cs558/finalp-anazar/testing$


- using command dir, the output should look like:
bank  client  Makefile  README.txt  server  testing



Make command: 
>>make

Clean command: 
>>make clean



How to initialize test.cpp (can be done anytime):
- For this, make sure to be inside subdirectory finalp-anazar/testing/
- Using dir on terminal, should look like (after make):
Prb.key  Prs.key  Pub.pem  Pus.pem  test  test.cpp

Format for test initialization:
>>./test


How to initialize bank side (complete before server and client side):
- For this, make sure to be inside subdirectory finalp-anazar/bank/
- Using dir on terminal, should look like (after make):
bank  bank.cpp  creditinfo.txt


Format for bank initialization:
>>./bank <bank’s port number>


(example after server created and where server side designated as anazar1@remote06:~/...)
>>./bank 2606



How to initialize server side (complete before client side):
- For this, make sure to be inside subdirectory finalp-anazar/server/
- Using dir on terminal, should look like (after make):
item.txt  serv  server.cpp


Format for server initialization:
>>./serv <bank’s domain name> <bank’s port number> <server’s port number>


(example after server created and where server side designated as anazar1@remote06:~/...)
>>./serv remote06.cs.binghamton.edu 2606 2607



How to initialize client side:
- For this, make sure to be inside subdirectory finalp-anazar/client/
- Using dir, should look like:
cli  client.cpp


Format for client initialization:
>>./cli <server_domain> <server_port>


(example after server created and where server side designated as anazar1@remote06:~/...)
>>./cli remote06.cs.binghamton.edu 2607

- Other commands will go through error handling

***************************************************************** Testing *****************************************************************
- After bank, server and client are initialized (testing file for the encryption/decryption can be initalized at any time), the user is sent
the "Items available for purchase" list which shows the <item #> <item> <price> parameters respectively. The client is asked to enter the
item number first, then enter the name followed by entering the credit card numbers. For clarity sake, the information for the users is as follows
where the name, credit card number and current balance are shown below (to test more, go to creditinfo.txt insive of server/ directory, then enter
the name, then MD5 hash of the equivalent card number where an online generator is preferred and set a burrent balance each separated by one space):

Information of current users:
Name: alice         Creditcardnumber: 12345678          Current balanace: 3000
Name: bob           Creditcardnumber: 23456789          Current balanace: 500
Name: warner        Creditcardnumber: 87654321          Current balanace: 45000


So take for instance that you're trying to purchase as warner, for item #, choose any from the item.txt or from the below:

Current Item List:
10000 table 100
10001 tv 2000
10002 lego 40
10003 lamp 20
10004 mansion 1000000

(i.e. Enter item number: 10003) Then enter name as warner (i.e. Enter your name: warner) and then the credit card for warner
(i.e. Enter your credit card number: 87654321). During the process, server and bank will print out messages of whats currently 
going on as well (i.e. where the message is being sent or connection status). Then if the order was confirmed or not is printed
on the client side and disconnects the client while keeping the server and bank listening for new users. Simply enter the same 
command that was used the first time for client to 'continue' shopping. When testing is over and want to quit server and/or bank,
Ctrl+C can be entered into the terminal.


Testing is a substitute for the openSSL errors and shows the value of messages before and after encyption/decryption using both
the public and private keys as well as signature and verification. I also printed out the MD5 has and verification status for
more clarification that the functions works as intended, just that openSSL was giving errors.


***************************************************************** EXTRA NOTES *****************************************************************
Signature RSA

Signature code:
// Function to sign a message using RSA private key
string signMessage(string message, RSA *privKey) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, privKey);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_SignInit(md_ctx, EVP_sha256());
    EVP_SignUpdate(md_ctx, message.c_str(), message.length());

    unsigned int sigLen;
    unsigned char *sig = (unsigned char *)malloc(EVP_PKEY_size(pkey));
    EVP_SignFinal(md_ctx, sig, &sigLen, pkey);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    string signature(reinterpret_cast<char *>(sig), sigLen);
    free(sig);

    return signature;
}



Verify RSA signature

// Function to verify a message using RSA public key
bool verifySignature(string message, string signature, RSA *pubKey) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, pubKey);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(md_ctx, EVP_sha256());
    EVP_VerifyUpdate(md_ctx, message.c_str(), message.length());

    int result = EVP_VerifyFinal(md_ctx, (const unsigned char *)signature.c_str(), signature.length(), pkey);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return result == 1;
}



Encryption code:

string encryptRSA(string plainText, RSA *pubKey) {
    int rsaLen = RSA_size(pubKey);
    unsigned char *cipherText = (unsigned char *)malloc(rsaLen);

    int cipherLen = RSA_public_encrypt(plainText.length(), (const unsigned char *)plainText.c_str(), cipherText, pubKey, RSA_PKCS1_OAEP_PADDING);
    if (cipherLen == -1) {
        cerr << "Error encrypting data" << endl;
        exit(1);
    }

    string encryptedText(reinterpret_cast<char *>(cipherText), cipherLen);
    free(cipherText);
    return encryptedText;
}



Decryption code:

string decryptRSA(string encryptedText, RSA *prvKey) {
    int rsaLen = RSA_size(prvKey);
    unsigned char *plainText = (unsigned char *)malloc(rsaLen);

    int plainLen = RSA_private_decrypt(encryptedText.length(), (const unsigned char *)encryptedText.c_str(), plainText, prvKey, RSA_PKCS1_OAEP_PADDING);
    if (plainLen == -1) {
        cerr << "Error decrypting data" << endl;
        exit(1);
    }

    string decryptedText(reinterpret_cast<char *>(plainText), plainLen);
    free(plainText);
    return decryptedText;
}