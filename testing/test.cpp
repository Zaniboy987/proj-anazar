#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/md5.h>
#include <iomanip>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define MAX_BUFFER_SIZE 1024
using namespace std;

// Function to encrypt using RSA private key
string encryptRSA(string plainText, RSA *pubKey) {
    int rsaLen = RSA_size(pubKey);
    unsigned char *cipherText = (unsigned char *)malloc(rsaLen);

    int cipherLen = RSA_public_encrypt(plainText.length(), (const unsigned char *)plainText.c_str(), cipherText, pubKey, RSA_PKCS1_OAEP_PADDING);
    if (cipherLen == -1) {
        cout << "Error encrypting data" << endl;
        free(cipherText);
        exit(1);
    }

    string encryptedText(reinterpret_cast<char *>(cipherText), cipherLen);
    free(cipherText);
    return encryptedText;
}

// Function to decrypt using RSA private key
string decryptRSA(string encryptedText, RSA *prvKey) {
    int rsaLen = RSA_size(prvKey);
    unsigned char *plainText = (unsigned char *)malloc(rsaLen);

    int plainLen = RSA_private_decrypt(encryptedText.length(), (const unsigned char *)encryptedText.c_str(), plainText, prvKey, RSA_PKCS1_OAEP_PADDING);
    if (plainLen == -1) {
        cout << "Error decrypting data" << endl;
        free(plainText);
        exit(1);
    }

    string decryptedText(reinterpret_cast<char *>(plainText), plainLen);
    free(plainText);
    return decryptedText;
}

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

int main(int argc, char *argv[]) {
    // Load server's private key
    FILE *serverPrvKeyFile = fopen("Prs.key", "r");
    RSA *serverPrvKey = PEM_read_RSAPrivateKey(serverPrvKeyFile, NULL, NULL, NULL);
    fclose(serverPrvKeyFile);

    // Load server's public key
    FILE *serverPublicKeyFile = fopen("Pus.pem", "r");
    RSA *serverPubKey = PEM_read_RSA_PUBKEY(serverPublicKeyFile, NULL, NULL, NULL);
    fclose(serverPublicKeyFile);

    // Load bank's private key
    FILE *privKeyFile = fopen("Prb.key", "r");
    RSA *bankPrivKey = PEM_read_RSAPrivateKey(privKeyFile, NULL, NULL, NULL);
    fclose(privKeyFile);

    // Load bank's public key
    FILE *bankPubKeyFile = fopen("Pub.pem", "r");
    RSA *bankPubKey = PEM_read_RSA_PUBKEY(bankPubKeyFile, NULL, NULL, NULL);
    fclose(bankPubKeyFile);

    cout << "Information to encrypt from client to server" << endl;

    // Prompt users to enter item number
    string itemNumber, name, creditCard;
    itemNumber = "10003", name = "alice", creditCard = "12345678";;
    cout << "Item number: " << itemNumber << endl;
    cout << "Name: " << name << endl;
    cout << "Credit card number: " << creditCard << endl;

    // Convert credit card number to MD5 hash
    unsigned char md5Hash[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *)creditCard.c_str(), creditCard.length(), md5Hash);
    stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)md5Hash[i];
    }
    string creditCardHash = ss.str();

    cout << endl << "MD5 Hash of Credit Card Number: " << creditCardHash << endl << endl;

    // Encrypt item number, name, and credit card hash w/ server's public key
    string encryptedMessage = encryptRSA(itemNumber + " " + name + " " + creditCardHash, serverPubKey);

    // Decrypt the message from client-->server
    string decryptedMessage = decryptRSA(encryptedMessage, serverPrvKey);
    stringstream ss_dec(decryptedMessage);
    string sitemNumber, sname, screditCard;
    ss_dec >> sitemNumber >> sname >> screditCard;

    cout << "Decrypted information from client:\n"
        << "Item #:" << sitemNumber << endl
        << "Name:" << sname << endl
        << "Credit Card Number:" << screditCard << endl;


    // Item file
    string fileprice = "20", filecreditCard;

    cout << "\nInformation (from item before encryption to bank):\n"
        << "Price #:" << fileprice << endl
        << "Name:" << sname << endl
        << "Credit Card Number:" << screditCard << endl;

    // Encrypt price, name, and credit card number using bank's public key
    encryptedMessage = encryptRSA(fileprice + " " + sname + " " + screditCard, bankPubKey);

    // Sign the encrypted message using server's private key
    string signature = signMessage(encryptedMessage, serverPrvKey);

    // Combine encrypted message and signature
    string signedMessage = encryptedMessage + signature;

    // Extract the received message and signature
    string receivedMessage = signedMessage.substr(0, signedMessage.length() - RSA_size(serverPubKey));
    string receivedSignature = signedMessage.substr(signedMessage.length() - RSA_size(serverPubKey));

    // Verify the signature using the server's public key
    if (!verifySignature(receivedMessage, receivedSignature, serverPubKey)) {
        cout << endl << "Failed to verify server's signature." << endl;
        exit(1);
    } else if (verifySignature(receivedMessage, receivedSignature, serverPubKey)) {
        cout << endl << "Succeeded in verifying server's signature" << endl;
    }

    // Decrypt the message from server-->bank
    decryptedMessage = decryptRSA(encryptedMessage, bankPrivKey);
    stringstream ss_dec1(decryptedMessage);
    string bankprice, bankname, bankcreditCard1;
    ss_dec1 >> bankprice >> bankname >> bankcreditCard1;

    cout << "\nDecrypting from bank:\n"
        << "Price #:" << bankprice << endl
        << "Name:" << bankname << endl
        << "Credit Card Number:" << bankcreditCard1 << endl;

    return 0;
}
