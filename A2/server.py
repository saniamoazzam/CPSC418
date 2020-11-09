# File creator: Sania Moazzam
# Run with: python Server.py

# Description: Calculates public variables N and g and listens for 
#	      client connections. Once it accepts a connection, it follows
#	      the outlined protocol to generate and verify a shared 
#	      authentication key.

import time
import sympy
import socket
import random
import secrets
from math import gcd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

HOST = "127.0.4.18"
PORT = 31802

def find_prime():
    N = 0
    while(sympy.isprime(N) == False):
        q = secrets.randbits(511)

        while(q.bit_length() != 511 or sympy.isprime(q) == False):
            q = secrets.randbits(511)  

        N = 2*q + 1
    return N

def primitive_root(N):
    for i in range(2, N): 
        if (gcd(i, N) == 1): 
            g = i
            break
    return g

def main():
    N = find_prime()
    g = primitive_root(N)
    digest = hashes.Hash(hashes.SHA256(), BACKEND)

    N_bytes = N.to_bytes(64, 'big')
    g_bytes = g.to_bytes(64, 'big')

    hash_str = N_bytes + g_bytes
    d1 = digest.copy()
    d1.update(hash_str)
    k_bytes = d1.finalize()
    k = int.from_bytes(k_bytes, 'big')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try: 
            sock.bind((HOST, PORT))
            print('Server listening...\n')
            print(f"Server: N = {N}")
            print(f"Server: g = {g}")

            sock.listen()
            conn, addr = sock.accept()

            with conn:
                print(f"Server: sending N <{N_bytes}>")
                print(f"Server: sending g <{g_bytes}>\n")
                conn.send(hash_str)
                clientdata = conn.recv(128)

                I = clientdata[1:5]
                usr_len = int.from_bytes(I, 'big')
                curr = 5+usr_len
                username = clientdata[5: curr]
                s = clientdata[curr: curr+16]
                v_bytes = clientdata[curr+16:]
                v = int.from_bytes(v_bytes, 'big')

                print(f"Server: I = {username}")
                print(f"Server: s = <{s}>")
                print(f"Server: v = {v}\n")

            print("Server: Registration successful\n")
        except Exception as e:
            print("Server: Registration unsuccessful\n")
            print(e)

        b = random.randint(0, N-1)
        tmp1 = pow(k*v, 1, N)
        tmp2 = pow(g, b, N)
        B = pow(tmp1+tmp2, 1, N)
        B_bytes = B.to_bytes(64, 'big')
        time.sleep(1)

        sock.listen()
        conn, addr = sock.accept()

        with conn:
            clientdata = conn.recv(128)
            A_bytes = clientdata[-64:]
            A = int.from_bytes(A_bytes, 'big')
            print(f"Server: I = {username}")
            print(f"Server: A = {A}\n")

            clientdata = s + B_bytes
            conn.send(clientdata)
            print(f"Server: sending s <{s}>")
            print(f"Server: sending B <{B_bytes}>\n")

            # Compute u ≡ H(A||B) (mod N)
            hash_str = A_bytes + B_bytes
            d2 = digest.copy()
            d2.update(hash_str)
            hashf = d2.finalize()
            u = pow(int.from_bytes(hashf, 'big'), 1, N)
            print(f"Server: u = {u}")
            print(f"Server: k = {k}\n")

            # Calculating k_server ≡ (Av^u)^b (mod N)
            tmp1 = pow(A, 1, N)
            tmp2 = pow(v, u, N)
            key = tmp1*tmp2
            k_server = pow(key, b, N)
            ks_bytes = k_server.to_bytes(64, 'big')
            print(f"Server: k_server = {k_server}\n")
            
            hash_str = A_bytes + B_bytes + ks_bytes
            d3 = digest.copy()
            d3.update(hash_str)
            test_bytes = d3.finalize()

            M_1 = conn.recv(1024)
            print(f"Server: M_1 <{M_1}>\n")


            if (M_1 == test_bytes):
                print("Server: Negotiation successful.")
            else:
                print("Server: Negotiation unsuccessful, aborting.")
                exit()

            hash_str = A_bytes + M_1 + ks_bytes
            d4 = digest.copy()
            d4.update(hash_str)
            M_2 = d4.finalize()
            conn.send(M_2)
            print(f"Server: sending M_2 <{M_2}>\n")


if __name__ == "__main__":
    BACKEND = default_backend()
    main()
