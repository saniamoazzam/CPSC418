# File creator: Sania Moazzam
# Run with: python Client.py
# Description: Asks user for a username and password. Then generates a
# 	      random salt value. Client computes v and sends a tuple to the
#	      server to register itself. Once registration is successful, 
# 	      it follows the outlined protocol to generate and verify a 
#	      shared authentication key.

import os
import time
import random
import string
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

HOST = "127.0.4.18"
PORT = 31802

def main():

    username = input("Enter a username: ")
    password = input("Enter a password: ")
    digest = hashes.Hash(hashes.SHA256(), BACKEND)

    # Encode the username and convert into a 4byte number in big-endian
    username = username.encode('utf-8')
    I = len(username).to_bytes(4, 'big')

    # Encode password into bytes
    password = password.encode('utf-8')

    # Generate salt s
    s = os.urandom(16)

    # Compute x = H(s||p):
    hash_str = s + password
    d1 = digest.copy()
    d1.update(hash_str)
    x_bytes = d1.finalize()
    x = int.from_bytes(x_bytes, 'big')

    # Generate random char r
    src = string.ascii_letters + string.punctuation
    r = random.choice(src)
    r = r.encode()
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.connect((HOST, PORT))
            response = conn.recv(128)

            # Read N and g as 64 byte numbers
            N_bytes = response[:64]
            g_bytes = response[64:]
            N = int.from_bytes(N_bytes, 'big')
            g = int.from_bytes(g_bytes, 'big')

            print(f"Client: N = {N}")
            print(f"Client: g = {g}\n")

            hash_str = N_bytes + g_bytes
            d2 = digest.copy()
            d2.update(hash_str)
            k_bytes = d2.finalize()
            k = int.from_bytes(k_bytes, 'big')

            # Compute v ≡ g^x (mod N)
            v = pow(g, x, N)    

            # Send tuple (‘r’, |I|, I, s, v) to the server 
            serverdata = r + I + username + s + v.to_bytes(64, 'big')
            print(f"Client: sending 'r' <{r.decode()}>")
            print(f"Client: sending |I| <{I}>")
            print(f"Client: sending I {username}")
            print(f"Client: sending s <{s}>")
            print(f"Client: sending v {v}\n")

            conn.send(serverdata)
        print("Client: Registration successful\n")
    except Exception as e:
        print("Client: Registration unsuccessful\n")
        print(e)

    a = random.randint(0, N-1)
    A = pow(g, a, N)
    A_bytes = A.to_bytes(64, 'big')
    serverdata = password + I + username + A_bytes
    time.sleep(1)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.connect((HOST, PORT))
            conn.send(serverdata)

            print(f"Client: sending p <{password}>")
            print(f"Client: sending |I| <{I}>")
            print(f"Client: sending username {username}")
            print(f"Client: sending A <{A_bytes}>\n")

            response = conn.recv(80)
            B_bytes = response[16:]
            B = int.from_bytes(B_bytes, 'big')
            print(f"Client: s = <{response[:16]}>")
            print(f"Client: B {B}\n")

            # Compute u ≡ H(A||B) (mod N)
            hash_str = A_bytes + B_bytes
            d3 = digest.copy()
            d3.update(hash_str) 
            hashf = d3.finalize()

            u = pow(int.from_bytes(hashf, 'big'), 1, N)
            print(f"Client: u = {u}")
            print(f"Client: k = {k}\n")


            # Compute K_client ≡ (B − kv)^a+ux (mod N)
            tmp1 = B-k*v
            tmp2 = a + u*x
            k_client = pow(tmp1, tmp2, N)
            kc_bytes = k_client.to_bytes(64, 'big')
            print(f"Client: k_client = {k_client}\n")

            # Compute M1 = H(A||B||Kclient)
            hash_str = A_bytes + B_bytes + kc_bytes
            d4 = digest.copy()
            d4.update(hash_str)
            M_1 = d4.finalize()

            print(f"Client: M_1 <{M_1}>")
            print(f"Client: sending M_1 <{M_1}>\n")
            conn.send(M_1)

            hash_str = A_bytes + M_1 + kc_bytes
            d5 = digest.copy()
            d5.update(hash_str)
            test_bytes = d5.finalize()

            M_2 = conn.recv(1024)
            print(f"Client: M_2 <{M_2}>\n")


            if (M_2 == test_bytes):
                print("Client: Negotiation successful.")
            else:
                print("Client: Negotiation unsuccessful, aborting.")
                exit()
    except Exception as e:
        print(e)


if __name__ == "__main__":
    BACKEND = default_backend()
    main()