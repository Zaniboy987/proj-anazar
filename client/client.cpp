#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <iomanip>
#define MAX_BUFFER_SIZE 1024
using namespace std;

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cout << "Usage: " << argv[0] << " <server’s domain name> <server’s port number>" << endl;
        exit(1);
    }

    char *serverDomain = argv[1];
    int serverPort = atoi(argv[2]);

    // Create socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        perror("Error creating socket");
        exit(1);
    }

    // Resolve server's domain name
    struct addrinfo hints, *serverAddr;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int status = getaddrinfo(serverDomain, NULL, &hints, &serverAddr);
    if (status != 0) {
        cout << "Error resolving server's domain name: " << gai_strerror(status) << endl;
        exit(1);
    }
    struct sockaddr_in *serverAddr_in = (struct sockaddr_in *)serverAddr->ai_addr;
    serverAddr_in->sin_port = htons(serverPort);

    // Connect to server
    if (connect(clientSocket, (struct sockaddr *)serverAddr_in, sizeof(*serverAddr_in)) == -1) {
        perror("Error connecting");
        exit(1);
    }
    cout << "Connected to server" << endl;

    // Receive items from server
    char buffer[MAX_BUFFER_SIZE] = {0};
    int valread = read(clientSocket, buffer, MAX_BUFFER_SIZE);
    cout << "Items available for purchase:\n" << buffer << endl;

    // Prompt users to enter item number
    string itemNumber, name, creditCard;
    cout << "Enter item number: ";
    cin >> itemNumber;
    cout << "Enter your name: ";
    cin >> name;
    cout << "Enter your credit card number: ";
    cin >> creditCard;

    // Convert credit card number to MD5 hash
    unsigned char md5Hash[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *)creditCard.c_str(), creditCard.length(), md5Hash);
    stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)md5Hash[i];
    }
    string creditCardHash = ss.str();

    // Encrypt item number, name, and credit card hash w/ server's public key
    string Msg = itemNumber + " " + name + " " + creditCardHash;

    // Send encrypted message to server
    send(clientSocket, Msg.c_str(), Msg.length(), 0);

    // Receive response from server
    valread = read(clientSocket, buffer, MAX_BUFFER_SIZE);
    string response(buffer, valread);
    if (response == "1") {
        cout << "Your order is confirmed" << endl;
    } else {
        cout << "Credit card transaction is unauthorized" << endl;
    }

    close(clientSocket);
    return 0;
}
