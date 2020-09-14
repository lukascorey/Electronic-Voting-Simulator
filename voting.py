#!/usr/bin/env python3

#Homework2, cpsc310 at Yale, spring 2019, Lukas Corey, Prof Feigenbaum
#This file sets up a local server and sockets to which two clients can connect and submit votes. 
#It keeps track of who votes for what candidate when and outputs that information after two votes. 
#It prevents people from voting more than once. Voter files are called client_1.py and client_2.py.


#line just so I can quickly find program on my computer 
# cd .\Desktop\Yale\2018_2019_Classes\cs310\hw2\voting\

#Sources: 
#https://realpython.com/python-sockets/
#https://stackoverflow.com/questions/10810249/python-socket-multiple-clients
#https://stackoverflow.com/questions/415511/how-to-get-the-current-time-in-python

import vote_crypto
import secrets
import time
import datetime
import socket
import _thread

#Initialize counts, list of who has voted, and audit trail
Rufus_T_Firefly_Votes = 0
Ambassador_Trentino_Votes = 0
voted_list = []
audit = []


#Function to detect voter input and process--increment counters, add voter to voted list, etc...
def on_new_client(clientsocket,addr):
    while True:
        msg = clientsocket.recv(4096)
        
        #checks if message has been received, only runs following code upon submission of a vote
        if msg:

        	#turns message into utf-8 
    	    msg = msg.decode('utf-8')
    	    print("encoded message received")

    	    #runs "receive" function to get decrypt, getting token, voter id, and candidate
    	    (rec_voter_id, rec_candidate, rec_token) = receive(msg)
    	    
    	    #print(" Voter_ID: ", rec_voter_id, "\n", "Candidate: ", rec_candidate, "\n", "Rec_Token ", rec_token)
    	    msg = "vote received"
    	    
    	    #Check if voter has already voted
    	    if rec_voter_id in voted_list:
    	    	msg = "You cannot vote again"
    	    	print("Duplicate vote not being counted")

    	    #Check who vote is for, and modify counts and audit	
    	    else:
    	    	voted_list.append(rec_voter_id)
    	    	if ("Firefly" in rec_candidate):	
    	    	    global Rufus_T_Firefly_Votes
    	    	    Rufus_T_Firefly_Votes = Rufus_T_Firefly_Votes + 1
    	    	    audit.append(rec_voter_id)
    	    	    audit.append(datetime.datetime.now())
    	    	    audit.append(rec_candidate)
    	    	    print("vote counted")
    	    	elif ("Trentino" in rec_candidate):
    	    	    global Ambassador_Trentino_Votes
    	    	    Ambassador_Trentino_Votes = Ambassador_Trentino_Votes + 1
    	    	    audit.append(rec_voter_id)
    	    	    audit.append(datetime.datetime.now())
    	    	    audit.append(rec_candidate)
    	    	    print("vote counted")
    	    	else:
    	    	    print("Vote not understood")
    	    
    	    #Send msg back to voter, either that vote was received or that they cannot revote
    	    clientsocket.send(msg.encode('utf-8'))

    	    #break out of while loop 
    	    break

    #Close connection
    clientsocket.close()

#function decrypts ciphertext message (provided from Prof Feigenbaum)
def receive(message):

	#Define two voter IDs and their public keys
    registry = {
        'vid_12345' : vote_crypto.client1[ 'public_key' ],
        'vid_12346' : vote_crypto.client1[ 'public_key' ]
    }

    ( ciphertext, signature ) = vote_crypto.decode( message )
    ( voter_id, candidate, token ) = vote_crypto.decrypt( vote_crypto.client2[ 'private_key' ], ciphertext )

    ( verified, ciphertext ) = vote_crypto.verify( registry[ voter_id ], ciphertext, signature )

    #Raises exception if invalid signature. Note: there is a bug here that stops the program if invalid signature. 
    if not verified:
        raise Exception( 'Invalid signature, vote not authenticated' )

    return ( voter_id, candidate, token )

def main():
	#Opens socket on local host 
	s = socket.socket()
	HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
	PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

	print("server started")
	print("waiting for clients")

	#listens for two connections 
	s.bind((HOST, PORT))
	s.listen(2)

	#while loop to accept connections 
	while True:
		c, addr = s.accept()     # Establish connection with client.
		_thread.start_new_thread(on_new_client,(c,addr))
		
		#delay to prevent too many votes at the same time
		time.sleep(2)


		#hard code in that there should be two votes 
		if (Rufus_T_Firefly_Votes + Ambassador_Trentino_Votes) == 2:
			print("votes for Firefly: ", Rufus_T_Firefly_Votes)
			print("votes for Trentino: ", Ambassador_Trentino_Votes)
			print("audit trail: ")

			#print out information from audit trail 
			for i in range(len(audit)//3):
				print("Vote #", (i + 1), "\n", "Voter ID: ", audit[3 * i], "\n", "Candidate: ", audit[3*i + 2], "\n", "Timestamp: ", audit[3*i + 1])
			break

	   #Notes from source of structure: 
	   #Note it's (addr,) not (addr) because second parameter is a tuple
	   #Edit: (c,addr)
	   #that's how you pass arguments to functions when creating new threads using thread module.

	#close socket
	s.close()
main()