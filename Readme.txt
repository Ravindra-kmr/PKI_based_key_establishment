This project was done as part of coursework CS6500 (Network Security) taught by Prof. Krishna Moorthy Sivalingam at IITM. Objective of this project is to establish a symmetric key using PKI (Public key Infrastructure) based key establishment and use it in algorithms.

This project demonstrate 2 concepts:
First, Generation of Certificate by CA (Certificate Authority).
Second, Exchange the Certificate between two parties and generate a symmetric key and use it to transfer a encrypted file.

* All programs are working and there are no bugs.
* Source code of sender and receiver is same.
* To create executable run


To generate RSA PUBLIC AND PRIVATE Key:
To create private key: openssl genrsa -aes-256-cbc -out private.pem 2048
To create corresponding public key: openssl rsa -in private.pem -outform PEM -pubout -out public.pem


RUN: $ ./cmd.sh

* Note Used latest version of Cryptography package (37.0)
To install it in your computer please follow following steps:
- $sudo python3 -m pip install -U pip3
- $sudo python3 -m pip install -U setuptools
- $curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
- $pip3 install -U cryptography




To run CA: Syntax:
./ca.py -p <portnumber> -o <outputfile>

To run sender: Syntax:
./client.py -n <Username> -m S -q <sender portnumber> -a <ca ip> -p <ca port>

To run receiver: Syntax:
./client.py -n <username> -m R -i <inputfile> -d <senderip> -q <sender port> -s <recvencryptedfile> -o <outputfile> -a <ca ip> -p <ca port>

Changes made in one of the message format (To support large length file transfer):
S -> R: 504 | FileName | EncrFileContentsLength |EncrFileContents

At the end RUN: make clean

