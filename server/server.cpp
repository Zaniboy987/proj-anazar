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

#define MAX_BUFFER_SIZE 1024
using namespace std;

int main(int argc, char *argv[]) {
    if (argc != 4) {
        cout << "Usage: " << argv[0] << " <bank’s domain name> <bank’s port number> <server’s port number>" << endl;
        exit(1);
    }

    char *bankDomain = argv[1];
    int bankPort = atoi(argv[2]);
    int serverPort = atoi(argv[3]);

    // Create server socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("Error creating server socket");
        exit(1);
    }

    // Create bank socket
    int bankSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (bankSocket == -1) {
        perror("Error creating bank socket");
        exit(1);
    }

    // Resolve bank's domain name
    struct hostent *bank = gethostbyname(bankDomain);
    if (bank == NULL) {
        cout << "Error resolving bank's domain name" << endl;
        exit(1);
    }

    // Prepare the bank address structure
    struct sockaddr_in bankAddr;
    memset(&bankAddr, 0, sizeof(bankAddr));
    bankAddr.sin_family = AF_INET;
    memcpy(&bankAddr.sin_addr.s_addr, bank->h_addr_list[0], bank->h_length);
    bankAddr.sin_port = htons(bankPort);

    // Connect to bank
    if (connect(bankSocket, (struct sockaddr *)&bankAddr, sizeof(bankAddr)) == -1) {
        perror("Error connecting to bank");
        exit(1);
    }
    cout << "Connected to bank..." << endl;

    // Bind the server socket to the address and server port number
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(serverPort);
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("Error binding server socket");
        close(serverSocket);
        exit(1);
    }
    int clientSocket;

    while (1) {
        // Start listening on the server socket
        if (listen(serverSocket, 1) == -1) {
            perror("Error listening on server socket");
            close(serverSocket);
            exit(1);
        }

        // Set up variables for select()
        fd_set readfds;
        int maxfd = max(serverSocket, bankSocket) + 1;
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);
        FD_SET(bankSocket, &readfds);

        // Accept connection from client or bank
        clientSocket = -1;
        while (clientSocket == -1) {
            if (select(maxfd, &readfds, NULL, NULL, NULL) == -1) {
                perror("Error in select");
                close(serverSocket);
                close(bankSocket);
                exit(1);
            }
            if (FD_ISSET(serverSocket, &readfds)) {
                // Accept connection from client
                clientSocket = accept(serverSocket, NULL, NULL);
                if (clientSocket == -1) {
                    perror("Error accepting client connection");
                    close(serverSocket);
                    close(bankSocket);
                    exit(1);
                }
                cout << "Connected to client" << endl;
                break;
            }
            if (FD_ISSET(bankSocket, &readfds)) {
                // Receive encrypted message from bank
                char buffer[MAX_BUFFER_SIZE] = {0};
                int valread = read(bankSocket, buffer, MAX_BUFFER_SIZE);
                if (valread == -1) {
                    perror("Error reading from bank");
                    close(serverSocket);
                    close(bankSocket);
                    exit(1);
                }

                // Decrypt message from bank
                string decryptedMessage = string(buffer);
                stringstream ss_dec(decryptedMessage);
                string itemNumber, name, creditCard;
                ss_dec >> itemNumber >> name >> creditCard;

                // Retrieve price of the item from items file
                ifstream itemsFile2("item.txt");
                string line;
                string price;
                while (getline(itemsFile2, line)) {
                    stringstream ss_item(line);
                    string itemId;
                    ss_item >> itemId;
                    if (itemId == itemNumber) {
                        ss_item >> price;
                        break;
                    }
                }
                itemsFile2.close();

                // Encrypt price, name, and credit card number using bank's public key
                string encryptedMessage = price + " " + name + " " + creditCard;

                // Send encrypted message to bank
                if (send(bankSocket, encryptedMessage.c_str(), encryptedMessage.length(), 0) == -1) {
                    perror("Error sending to bank");
                    close(serverSocket);
                    close(bankSocket);
                    exit(1);
                }
            }
        }

        // Load items from file
        ifstream itemsFile("item.txt");
        stringstream ss;
        ss << itemsFile.rdbuf();
        string items = ss.str();
        itemsFile.close();

        // Send items to client
        if (send(clientSocket, items.c_str(), items.length(), 0) == -1) {
            perror("Error sending to client");
            close(clientSocket);
            close(serverSocket);
            close(bankSocket);
            exit(1);
        }

        // Receive encrypted message from client
        char buffer[MAX_BUFFER_SIZE] = {0};
        int valread = read(clientSocket, buffer, MAX_BUFFER_SIZE);
        if (valread == -1) {
            perror("Error reading from client");
            close(clientSocket);
            close(serverSocket);
            close(bankSocket);
            exit(1);
        }

        // Decrypt message from client
        string decryptedMessage = string(buffer);
        stringstream ss_dec(decryptedMessage);
        string itemNumber, name, creditCard;
        ss_dec >> itemNumber >> name >> creditCard;

        // Retrieve price of the item from items file
        ifstream itemsFile2("item.txt");
        string line;
        string price;
        while (getline(itemsFile2, line)) {
            stringstream ss_item(line);
            string itemId, itemName;
            int itemPrice;
            ss_item >> itemId >> itemName >> itemPrice;
            if (itemId == itemNumber) {
                price = to_string(itemPrice);
                break;
            }
        }
        itemsFile2.close();

        // Encrypt price, name, and credit card number using bank's public key
        string encryptedMessage = price + " " + name + " " + creditCard;

        // Send encrypted message to bank
        if (send(bankSocket, encryptedMessage.c_str(), encryptedMessage.length(), 0) == -1) {
            perror("Error sending to bank");
            close(clientSocket);
            close(serverSocket);
            close(bankSocket);
            exit(1);
        }
        cout << "Sent message to bank..." << endl;

        // Receive response from bank
        valread = read(bankSocket, buffer, MAX_BUFFER_SIZE);
        if (valread == -1) {
            perror("Error reading from bank");
            close(clientSocket);
            close(serverSocket);
            close(bankSocket);
            exit(1);
        }
        string response(buffer, valread);

        // Send response to client
        if (send(clientSocket, response.c_str(), response.length(), 0) == -1) {
            perror("Error sending to client");
            close(clientSocket);
            close(serverSocket);
            close(bankSocket);
            exit(1);
        }
        cout << "Sent message to client..." << endl;
    }

    close(clientSocket);
    close(serverSocket);
    close(bankSocket);

    return 0;
}
