# File creator: Sania Moazzam
# Run with: python3 client.py file 

# Description: connects to TTP and gets its RSA parameters to verify signature from server. 
#           Then connects to server, establishes a verified connection, verifies 
#           TTP_SIGNATURE then derives a shared key with server. Sends 
#		    encrypted file to server. The file is read from stdin when 
#            client is started. Run with python3 client.py file

import os
import time
from shared import *


def main(argv):
    # Read in file to be encrypted
    with open(argv[1], "rb") as fd:
        byte_text = fd.read()
    
    # User inputs username and password
    username = input("Enter a username: ")
    I = username.encode('utf-8')
    I_len = len(I).to_bytes(4, 'big')

    password = input("Enter a password: ")
    password = password.encode('utf-8')
    
    # Connect to TTP 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ttp_sock:
        PORT = 31802
        ttp_sock.connect((HOST, PORT))
        request = "REQUEST KEY".encode('utf-8')
        ttp_sock.send(request)

        # Recieve TTP public key
        response = ttp_sock.recv(256)
        TTP_N = int.from_bytes(response[:128], 'big')
        TTP_e = int.from_bytes(response[128:], 'big')

        print(f"Client: Received TTP_N = {TTP_N}")
        print(f"Client: Received TTP_e = {TTP_e}\n")
    
    PORT = 31803
    digest256 = hashes.Hash(hashes.SHA3_256(), BACKEND)

    # Generate salt s
    s = os.urandom(16)
    print(f"Client: salt = <{s}>")

    # Compute x = H(s||p):
    hash_str = s + password
    d1 = digest256.copy()
    d1.update(hash_str)
    x_bytes = d1.finalize()
    x = int.from_bytes(x_bytes, 'big')
    print(f"Client: x = {x}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.connect((HOST, PORT))
            response = conn.recv(128)

            # Read N and g as 64 byte numbers
            N_bytes = response[:64]
            g_bytes = response[64:]
            N = int.from_bytes(N_bytes, 'big')
            g = int.from_bytes(g_bytes, 'big')

            print(f"Client: N = {N}")
            print(f"Client: g = {g}")

            # Calculate k
            hash_str = N_bytes + g_bytes
            d2 = digest256.copy()
            d2.update(hash_str)
            k_bytes = d2.finalize()
            k = int.from_bytes(k_bytes, 'big')

            # Compute v ≡ g^x (mod N)
            v = pow(g, x, N) 
            v_bytes = v.to_bytes(64, 'big')
            print(f"Client: v = {v}\n")
            print(f"Client: k = {k}\n")

            # Registeration with server
            data = I_len + I + s + v_bytes
            print(f"Client: Sending (|I|, I, s, v)")
            print(f"Client: Sending len(username) <{I_len}>")
            print(f"Client: Sending username <{I}>")
            print(f"Client: Sending salt <{s}>")
            print(f"Client: Sending v <{v_bytes}>")

            conn.send(data)
            print("Client: Registration successful\n")

    time.sleep(5)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.connect((HOST, PORT))
            response = conn.recv(128)

            # Read N and g as 64 byte numbers
            N_bytes = response[:64]
            g_bytes = response[64:]
            N = int.from_bytes(N_bytes, 'big')
            g = int.from_bytes(g_bytes, 'big')

            print(f"Client: N = {N}")
            print(f"Client: g = {g}")

            data = I_len + I
            print(f"Client: Sending (|I|, I)")
            print(f"Client: Sending len(username) <{I_len}>")
            print(f"Client: Sending username <{I}>")
            conn.send(data)

            # Receive server certificate
            server_cert = conn.recv(1024)
            print(f"Client: Received Server_certificate <{server_cert}>\n")

            S_len = int.from_bytes(server_cert[:4], 'big')
            curr = 4+S_len
            S = server_cert[4: curr]
            server_Nb = server_cert[curr: curr+128]
            server_eb = server_cert[curr+128: curr+256]
            TTP_SIG_b = server_cert[curr+256:]

            server_e = int.from_bytes(server_eb, 'big')
            server_N = int.from_bytes(server_Nb, 'big')
            TTP_SIG = int.from_bytes(TTP_SIG_b, 'big')

            print(f"Client: S = '{S.decode('utf-8')}'")
            print(f"Client: server_N = {server_N}")
            print(f"Client: server_e = {server_e}")
            print(f"Client: TTP_SIG = {TTP_SIG}")

            # Verify signature of TTP   
            # Calculate t 
            array = S + server_Nb + server_eb
            d1 = digest512.copy()
            d1.update(array)
            t_bytes = d1.finalize()

            # Calculate t1
            d2 = digest512.copy()
            d2.update(t_bytes)
            t1_bytes = d2.finalize()

            # t || t1 reduced by modulus n
            tt1_bytes = t_bytes + t1_bytes
            tt1 = int.from_bytes(tt1_bytes, 'big')
            tt1_red = pow(tt1, 1, TTP_N)
                               
            if verification(TTP_SIG_b, tt1_red, TTP_e, TTP_N):
                print("Client: TTP signature verified\n")
            else:
                print("\nClient: Unable to verify TTP signature")
                return

            # SRP Protocol follows
            # Generate a
            a = random.randint(0, N-1)
            print( f"Client: a = {a}")

            # Calculate Enc(A)
            A = pow(g, a, N)
            A_bytes = A.to_bytes(128, 'big')
            print(f"Client: A = {A}" )

            # Encrypt A with RSA 
            Enc_A = encrypt(A, server_e, server_N)
            EncA_bytes = Enc_A.to_bytes(128, 'big')

            # Send (I, Enc(A))
            serverdata = I + EncA_bytes
            print(f"Client: Sending Enc(A) = <{A_bytes}>")
            conn.send(serverdata)

            # Receive (s, B)
            response = conn.recv(144)
            B_bytes = response[16:]
            B = int.from_bytes(B_bytes, 'big')
            print(f"Client: Received salt = <{response[:16]}>")
            print(f"Client: Received B = {B}")

            # Compute u ≡ H(A||B) (mod N)
            hash_str = A_bytes + B_bytes
            d3 = digest256.copy()
            d3.update(hash_str) 
            hashf = d3.finalize()

            u = pow(int.from_bytes(hashf, 'big'), 1, N)
            print(f"Client: u = {u}")

            # Compute K_client ≡ (B − kv)^a+ux (mod N)
            tmp1 = B-k*v
            tmp2 = a + u*x
            k_client = pow(tmp1, tmp2, N)
            kc_bytes = k_client.to_bytes(64, 'big')
            print(f"Client: k_client = {k_client}\n")

            # Compute M1 = H(A||B||Kclient)
            hash_str = A_bytes + B_bytes + kc_bytes
            d4 = digest256.copy()
            d4.update(hash_str)
            M_1 = d4.finalize()

            print(f"Client: M_1 = {int.from_bytes(M_1, 'big')}")
            print(f"Client: sending M_1 <{M_1}>\n")
            conn.send(M_1)

            # Compute M2 test
            hash_str = A_bytes + M_1 + kc_bytes
            d5 = digest256.copy()
            d5.update(hash_str)
            test_bytes = d5.finalize()

            M_2 = conn.recv(1024)

            print(f"Client: Received M_2 = <{M_2}>\n")

            if (M_2 == test_bytes):
                print("Client: Negotiation successful.")
            else:
                print("Client: Negotiation unsuccessful, aborting.")
                return 0

            # Encrypt and authenticate the file 
            # Create H(shared_key)
            hash_digest = hashes.Hash(hashes.SHA3_256(), BACKEND)
            tag2 = hash_digest.copy()
            tag2.update(kc_bytes)
            key_hash = tag2.finalize()

            # Create H(file)
            hash_digest = hashes.Hash(hashes.SHA3_256(), BACKEND)
            tag2 = hash_digest.copy()
            tag2.update(byte_text)
            hash_file = tag2.finalize()

            # plaintext (in bytes) || Hash (plaintext)
            to_pad = byte_text + hash_file

            # Pads B_hash if block size < 16
            size = len(to_pad)
            if size % 16 != 0:
                padder = padding.PKCS7(128).padder()
                to_encrpt = padder.update(to_pad) + padder.finalize()
            else:
                to_encrpt = to_pad

            # Encrypt using AES-256-CBC
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key_hash), modes.CBC(iv), BACKEND)
            encryptor = cipher.encryptor()
            cipher_text = encryptor.update(to_encrpt) + encryptor.finalize()
            
            # Server tag = len(iv + ciphertext) + iv + cipher_text
            server_tag = iv + cipher_text
            lb = len(server_tag).to_bytes(4, 'big')
            server_tag = lb + server_tag
            conn.send(server_tag)
            

if __name__ == "__main__":
    main(sys.argv)