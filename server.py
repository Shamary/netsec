# Server to implement simplified RSA algorithm. 
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server. The server then sends
# a nonce (number used once) to the client, encrypted with the server's private
# key. The client decrypts that nonce and sends it back to server encrypted 
# with the session key. 

# Author: fokumdt 2015-11-02

#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import simplified_AES

def expMod(b,n,m):
	"""Computes the modular exponent of a number"""
	"""returns (b^n mod m)"""
	if n==0:
		return 1
	elif n%2==0:
		return expMod((b*b)%m, n/2, m)
	else:
		return(b*expMod(b,n-1,m))%m


def RSAencrypt(m, e, n):
        return expMod(m,e,n);


def RSAdecrypt(c, d, n):
	"""Decryption side of RSA"""
	# Fill in the code to do RSA decryption

	return expMod(c,d,n);
        

def gcd_iter(u, v):
    """Iterative Euclidean algorithm"""
    while v:
        u, v = v, u % v
    return abs(u)

def ext_Euclid(m,n):
    """Extended Euclidean algorithm"""
    # Provide the rest of the code to use the extended Euclidean algorithm
    # Refer to the project specification.
    a1,a2,a3= 1,0,m;
    b1,b2,b3= 0,1,n;

    while(True):
            if(b3==0):
                    return a3;
            elif(b3==1):
                    #b2=(math.pow(n,-1)%m);
                    return b2;
            q=math.floor(a3/b3);

            t1,t2,t3=(a1-q*b1),(a2-q*b2),(a3-q*b3);
            a1,a2,a3= b1,b2,b3;
            b1,b2,b3= t1,t2,t3;

def generateNonce():
	"""This method returns a 16-bit random integer derived from hashing the
	    current time. This is used to test for liveness"""
	hash = hashlib.sha1()
	hash.update(str(time.time()).encode('utf-8'))
	return int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)



def calc_e(n,phi_n): #calculates the value for e which must be less than n and coprime to the totient
        """Encryption side of RSA"""
        # Fill in the code to do RSA encryption

        l=[];#list of possible e values
        
        max_r=round(phi_n/1000);#values are obtained up to .001(phi(b))-1 to reduce time taken on finding e values
        
        for i in range(2,max_r): 
                init=True;#flag used to identify if a number 'i' is coprime to phi(n) 
                
                for j in range(2,i+1):
                        if(init and i%j==0 and phi_n%j==0):#true if they are not coprime
                                #print("e= "+j);
                                #return j;
                                init=False;
                if(init):
                        l+=[i];#if coprime to totient then add i to list of e values
                        #init=False;
                        #print(l);
        
        return l[round(random.random()*(len(l)-1))];#choose a random e value from the possible values


def genKeys(p, q):
        """Generate n, phi(n), e, and d."""
        # Fill in code to generate the server's public and private keys.
        # Make sure to use the Extended Euclidean algorithm.
        n=p*q;
        phi_n=(p-1)*(q-1);

        e= calc_e(n,phi_n);

        d=ext_Euclid(phi_n,e);

        print("n= "+str(n)+"\ntotient(n)= "+str(phi_n)+"\nd= "+str(d)+"\ne= "+str(e));

        return n,e,d;


def clientHelloResp(n, e):
    """Responds to client's hello message with modulus and exponent"""
    status = "105 Hello "+ str(n) + " " + str(e)
    return status

def SessionKeyResp(nonce):
    """Responds to session key with nonce"""
    status = "113 Nonce "+ str(nonce)
    return status

def nonceVerification(nonce, decryptedNonce):
        """Verifies that the transmitted nonce matches that received
        from the client."""
        #Enter code to compare the nonce and the decryptedNonce. This method
        # should return a string of "200 OK" if the parameters match otherwise
        # it should return "400 Error Detected"
        if(nonce==decryptedNonce):
                return("200 OK");
        else:
                return("400 Error Detected");
        

HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 9000               # Arbitrary non-privileged port
strHello = "100 Hello"
strHelloResp = "105 Hello"
strSessionKey = "112 SessionKey"
strSessionKeyResp = "113 Nonce"
strNonceResp = "130"
strServerStatus = ""
print ("Enter prime numbers. One should be between 907 and 1013, and the other\
 between 53 and 67")
p = int(input('Enter P : '))
q = int(input('Enter Q: '))
# You should delete the next three lines. They are included so your program can
# run to completion
#n = 67871
#e = 5
#d= 26717
n, e, d = genKeys(p, q)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# The next line is included to allow for quicker reuse of a socket.
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)
conn, addr = s.accept()
print('\n\nConnected by', addr)
data = conn.recv(1024).decode('utf-8')
if data and data.find(strHello) >= 0:

    print("Received "+str(data)+" from client");
        
    msg = clientHelloResp(n, e)

    print("Sending response...");
	
    conn.sendall(bytes(msg, 'utf-8'))

    print("Response sent as "+msg+" (Public key)");


    data = conn.recv(1024).decode('utf-8')

    print("Received "+str(data)+" from client");
	
    if data and data.find(strSessionKey) >= 0:
		# Add code to parse the received string and extract the symmetric key
        SymmKey = RSAdecrypt(int((data[15:])),d,n); # Make appropriate function call to decrypt the symmetric key
        print("\nSymmetric key= "+str(SymmKey));

		# The next line generates the round keys for simplified AES
        simplified_AES.keyExp(SymmKey)
        challenge = generateNonce();
        msg = SessionKeyResp(RSAencrypt(challenge,d,n));
		
        print("Nounce to be sent is "+str(challenge));
		
        print("Sending message "+str(msg)+"... ");
        conn.sendall(bytes(msg,'utf-8'))
        print("Message sent.");
		
        data = conn.recv(1024).decode('utf-8')
        print("Received "+str(data)+" from client");
		
        if data and data.find(strNonceResp) >= 0:
			# Add code to parse the received string and extract the nonce
            encryptedChallenge=int(data[4:]);
			# The next line runs AES decryption to retrieve the key.
            decryptedChallenge = simplified_AES.decrypt(encryptedChallenge)
            
            print("Encrypted challenge= "+str(encryptedChallenge)+" decrypted Challenge= "+str(decryptedChallenge));
            
            msg = nonceVerification(challenge, decryptedChallenge)# Make function call to compare the nonce sent with that received

            print("Sending message... ");
            conn.sendall(bytes(msg,'utf-8'))
            print("Message "+ msg+" sent.");
			
conn.close()
