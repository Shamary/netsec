# Client to implement simplified RSA algorithm.
# The client says hello to the server, and the server responds with a Hello
# and its public key. The client then sends a session key encrypted with the
# server's public key. The server responds to this message with a nonce
# encrypted with the server's public key. The client decrypts the nonce
# and sends it back to the server encrypted with the session key. Finally,
# the server sends the client a message with a status code.
# Author: fokumdt 2015-10-18

#!/usr/bin/python3

import socket
import math
import random
import simplified_AES


def expMod(b,n,m):
        """Computes the modular exponent of a number returns (b^n mod m)"""
        if n==0:
                return 1
        elif n%2==0:
                return expMod((b*b)%m, n/2, m)
        else:
                return(b*expMod(b,n-1,m))%m

def RSAencrypt(m, e, n):
        """Encryption side of RSA"""
        # Write code to do RSA encryption
        return expMod(m,e,n);

def RSAdecrypt(c, d, n):
        """Decryption side of RSA"""
        # Write code to RSA decryption
        return expMod(c,d,n);

def serverHello():
        """Sends server hello message"""
        status = "100 Hello"
        return status

def sendSessionKey(s):
        """Sends server session key"""
        status = "112 SessionKey " + str(s)
        return status

def sendTransformedNonce(xform):
        """Sends server nonce encrypted with session key"""
        status = "130 " + str(xform)
        return status

def computeSessionKey():
        """Computes this node's session key"""
        sessionKey = random.randint(1, 32768)
        return sessionKey
        


def main():
        """Driver function for the project"""
        serverHost = 'localhost'        # The remote host
        serverPort = 9000               # The same port as used by the server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((serverHost, serverPort))

        print("Connected to server...");

        
        msg = serverHello()
        s.sendall(bytes(msg,'utf-8'))  # Sending bytes encoded in utf-8 format.

        print("message "+msg+" sent");
        
        data = s.recv(1024).decode('utf-8')
        print("Message "+str(data)+" received");
        
        strStatus = "105 Hello"
        if data and data.find(strStatus) < 0:
                print("Invalid data received. Closing")
        else:
                # Write appropriate code to parse received string and extract
                # the modulus and exponent for public key encryption.
                
                tn="";
                te="";
                space=False;
                for k in data[10:]:
                        if(k!=" " and not space):#gets n segment
                                tn+=str(k);
                        elif(k==" "):
                                space=True;
                        elif(space):#gets e segment
                                te+=str(k); 
                                
                n = int(tn) # Modulus for public key encryption
                e =  int(te)# Exponent for public key encryption
                print("Server's public key: ("+ str(n)+","+str(e)+")")
                
                symmetricKey = computeSessionKey()
                
                encSymmKey = RSAencrypt(symmetricKey, e, n)
                print("Sending symmetric key "+str(symmetricKey)+"...");
                msg = sendSessionKey(encSymmKey)
                print("Key "+str(msg)+" sent.");
                s.sendall(bytes(msg,'utf-8'))
                
                data = s.recv(1024).decode('utf-8')
                print("Received "+str(data)+" from server");

                
                strStatus = "113 Nonce"
                if data and data.find(strStatus) < 0:
                        print("Invalid data received. Closing")
                else:
                        # Write code to parse received string and extract encrypted nonce
                        # from the server. The nonce has been encrypted with the server's
                        # private key.
                        encNonce=int(data[10:]);
                        print("Encrypted nonce: "+ str(encNonce))
                        nonce = RSAdecrypt(encNonce, e, n)
                        print("Decrypted nonce: "+ str(nonce))
                        """Setting up for Simplified AES encryption"""
                        plaintext = nonce
                        simplified_AES.keyExp(symmetricKey) # Generating round keys for AES.
                        ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
                        msg = sendTransformedNonce(ciphertext)
                        s.sendall(bytes(msg,'utf-8'))

                        print("Message "+ msg+" sent.");
                        
                        data = s.recv(1024).decode('utf-8')
                        if data:
                                print(data)
        s.close()

if __name__ == "__main__":
    main()
