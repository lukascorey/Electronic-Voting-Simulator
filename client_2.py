#!/usr/bin/env python3

#Homework2, cpsc310 at Yale, spring 2019, Lukas Corey, Prof Feigenbaum
#sends vote to server from voter id vid_12346 for candidate Ambassador Trentino with random token. 
#connects to local host via port 65432 and encrypts message with provided "send" function. 

import vote_crypto
import secrets
import socket
import _thread

#function to encrypt and sign plaintext into ciphertext 
def send( voter_id, candidate, token ):

    ciphertext = vote_crypto.encrypt( vote_crypto.client2[ 'public_key' ], voter_id, candidate, token )
    signature  = vote_crypto.sign( vote_crypto.client1[ 'private_key' ], ciphertext )
    message    = vote_crypto.encode( ciphertext, signature )

    return message


def main():
    #set up socket connection to local host 
    HOST = '127.0.0.1'  # The server's hostname or IP address
    PORT = 65432        # The port used by the server

    #connects to host
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        #vote information, random token
        voter_id  = 'vid_12346'
        candidate = 'Ambassador Trentino'
        token     = secrets.token_hex( 16 )

        #encrypts and signs
        ciphertext = send( voter_id, candidate, token )

        #sends vote
        s.sendall(ciphertext.encode('utf-8'))

        #receives message back from server to confirm submission
        data = s.recv(4096).decode('utf-8')

        #prints message
        print(repr(data))
main()