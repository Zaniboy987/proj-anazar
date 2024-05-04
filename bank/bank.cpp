#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <iomanip>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <cstdio>
#include <cstdlib>

#define MAX_BUFFER_SIZE 1024
using namespace std;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <bank’s port number>" << endl;
        exit(1);
    }

    int bankPort = atoi(argv[1]);

    // Load credit info
    ifstream creditInfoFile("creditinfo.txt");
    string creditInfoData;
    if (creditInfoFile.is_open()) {
        stringstream buffer;
        buffer << creditInfoFile.rdbuf();
        creditInfoData = buffer.str();
    }
    creditInfoFile.close();

    
    // Create socket
    int bankSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (bankSocket == -1) {
        perror("Error creating socket");
        exit(1);
    }

    // Bind socket
    struct sockaddr_in bankAddr;
    bankAddr.sin_family = AF_INET;
    bankAddr.sin_port = htons(bankPort);
    bankAddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(bankSocket, (struct sockaddr *)&bankAddr, sizeof(bankAddr)) == -1) {
        perror("Error binding");
        exit(1);
    }

    // Listen for connections
    if (listen(bankSocket, 5) == -1) {
        perror("Error listening");
        exit(1);
    }
    cout << "waiting for server connection..." << endl;

    // Accept connections
    struct sockaddr_in serverAddr;
    socklen_t serverAddrSize = sizeof(serverAddr);
    int serverSocket = accept(bankSocket, (struct sockaddr *)&serverAddr, &serverAddrSize);
    if (serverSocket == -1) {
        perror("Error accepting connection");
        exit(1);
    }
    cout << "got connection from server..." << endl; // switches from listening to server to client

    while (true) {
        // Load credit info
        ifstream creditInfoFile("creditinfo.txt");
        string creditInfoData;
        if (creditInfoFile.is_open()) {
            stringstream buffer;
            buffer << creditInfoFile.rdbuf();
            creditInfoData = buffer.str();
        }
        creditInfoFile.close();

        // Receive message from server
        char buffer[MAX_BUFFER_SIZE] = {0};
        int valread = read(serverSocket, buffer, MAX_BUFFER_SIZE);
        if (valread == -1) {
            perror("Error reading from server");
            close(serverSocket);
            continue;
        } else if (valread == 0) {
            cout << "Server closed connection" << endl;
            close(serverSocket);
            continue;
        }

        // Extract item number, customer name, and credit card number
        stringstream ss(buffer);
        string price, customerName, creditCardNumber;
        ss >> price >> customerName >> creditCardNumber;

        // Check credit info and update
        stringstream creditStream(creditInfoData);
        string line;
        string name, hash, credit;
        bool found = false;
        while (getline(creditStream, line)) {
            stringstream ss(line);
            ss >> name >> hash >> credit;
            if (name == customerName && hash == creditCardNumber) {
                int availableCredit, itemPrice;
                istringstream (credit) >> availableCredit;
                istringstream (price) >> itemPrice;
                if (availableCredit >= itemPrice) {
                    availableCredit -= itemPrice;
                    found = true;
                    // Update credit info file
                    string newCreditInfoData;
                    creditStream.seekg(0);
                    while (getline(creditStream, line)) {
                        if (line.find(name) != string::npos && line.find(hash) != string::npos) {
                            newCreditInfoData += name + " " + hash + " " + to_string(availableCredit) + "\n";
                        } else {
                            newCreditInfoData += line + "\n";
                        }
                    }
                    ofstream outFile("creditinfo.txt");
                    outFile << newCreditInfoData;
                    outFile.close();
                    // Send response to server
                    cout << "Sent message to bank..." << endl;
                    send(serverSocket, "1", strlen("1"), 0);
                    break;
                }
            }
        }

        if (!found) {
            // Send response to server
            cout << "Sent message to bank..." << endl;
            send(serverSocket, "0", strlen("0"), 0);
        }
    }
    close(bankSocket);
    return 0;
}
