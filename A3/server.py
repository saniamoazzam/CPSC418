# File creator: Sania Moazzam
# Run with: python3 server.py filename
# Description: connects to TTP and gets TTP_SIGNATURE, calculates public variables N and g, 
#           creates RSA parameters for itself. Then establishes a connected with client, 
#           sends its certificate, derives a shared secret with client. 
#           Then it waits for client to send file and outputs the decrypted file

import time
from shared import *


def primitive_root(N):
    for i in range(2, N): 
        if (gcd(i, N) == 1): 
            return i


def main(argv):
    decrypted_filename = argv[1]

    # Get server name 
    server_name = input("Enter a name for the server: ")
    S = server_name.encode('utf-8')
    S_len = len(S).to_bytes(4, 'big')

    # Generate RSA key pairs
    public_key, private_key = parameters()
    server_N = public_key[0]
    server_e = public_key[1]
    server_d = private_key[0]
    server_p = private_key[1]
    server_q = private_key[2]

    server_e_bytes = server_e.to_bytes(128, 'big')
    server_N_bytes = server_N.to_bytes(128, 'big')

    print(f"Server: Server_N = {server_N}")
    print(f"Server: Server_e = {server_e}")
    print(f"Server: Server_d = {server_d}")
    print(f"Server: Server_p = {server_p}")
    print(f"Server: Server_q = {server_q}\n")


    # Connect to TTP 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ttp_sock:
        PORT = 31802
        ttp_sock.connect((HOST, PORT))
        request = "REQUEST SIGN".encode('utf-8')
        ttp_sock.send(request)
        del request

        # Process and send data to TTP
        ttp_data = S_len + S + server_N_bytes + server_e_bytes
        ttp_sock.send(ttp_data)
        print(f"Server: Sending len(S) = <{S_len}>")
        print(f"Server: Sending S = <{S}>")
        print(f"Server: Sending server_N = <{server_N_bytes}>")
        print(f"Server: Sending server_e = <{server_e_bytes}>")
        del ttp_data

        # Receive TTP signature
        ttp_data = ttp_sock.recv(256)
        TTP_N_b = ttp_data[:128]
        TTP_SIG_b = ttp_data[128:]
        TTP_SIG = int.from_bytes(TTP_SIG_b, 'big') 
        TTP_N = int.from_bytes(TTP_N_b, 'big') 

        print(f"Server: Received TTP_signature = {TTP_SIG}")
        print(f"Server: Received TTP_N = {TTP_N}")


    digest256 = hashes.Hash(hashes.SHA3_256(), BACKEND)
    PORT = 31803

    # Public variables
    N = safeprime()
    g = primitive_root(N)
    print(f"Server: N = {N}")
    print(f"Server: g = {g}")

    N_bytes = N.to_bytes(64, 'big')
    g_bytes = g.to_bytes(64, 'big')

    # Calculate k
    hash_str = N_bytes + g_bytes
    d1 = digest256.copy()
    d1.update(hash_str)
    k_bytes = d1.finalize()
    k = int.from_bytes(k_bytes, 'big')
    print(f"Server: k = {k}")

    # Connect to client
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        print('Server listening...\n')
            
        sock.listen()
        conn, addr = sock.accept()

        with conn:
            print(f"Server: sending N <{hex(N)}>")
            print(f"Server: sending g <{hex(g)}>\n")
            conn.send(hash_str)
                
            # Receive client tuple (|I|, I,s,v)
            clientdata = conn.recv(128)
            I_len = int.from_bytes(clientdata[:4], 'big')
            curr = 4+I_len
            I = clientdata[4: curr]
            client_s = clientdata[curr: curr+16]
            v_bytes = clientdata[curr+16:]
            v = int.from_bytes(v_bytes, 'big')

            print(f"Server: Received I = '{I.decode('utf-8')}'")
            print(f"Server: Received client_salt = <{client_s}>")
            print(f"Server: Received v = {v}")

            print("Server: Registration successful\n")


    time.sleep(5)
    # Connect to client
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        print('Server listening...\n')
            
        sock.listen()
        conn, addr = sock.accept()

        with conn:
            hash_str = N_bytes + g_bytes
            print(f"Server: sending N <{hex(N)}>")
            print(f"Server: sending g <{hex(g)}>\n")
            conn.send(hash_str)

            # Receive client tuple (|I|, I)
            clientdata = conn.recv(I_len+4)
            print(f"Server: Received I = '{clientdata[4:].decode('utf-8')}'")
            if (clientdata[4:] != I):
                print("Unkown client")
                return

            # Creating server certificate
            certificate = S_len + S + server_N_bytes + server_e_bytes + TTP_SIG_b
            print(f"Server: Sending len(S) = <{S_len}>")
            print(f"Server: Sending S = <{S}>")
            print(f"Server: Sending server_N = <{server_N_bytes}>")
            print(f"Server: Sending server_e = <{server_e_bytes}>")
            print(f"Server: Sending TTP_SIG = <{TTP_SIG_b}>")

            print(f"Server: Sending Server_certificate <{certificate}>\n")
            conn.send(certificate)

            # SRP Protocol follows
            # Generate b 
            b = random.randint(0, N-1)
            print( f"Server: b = {b}")

            # B = kv + g^b mod N
            tmp1 = pow(k*v, 1, N)
            tmp2 = pow(g, b, N)
            B = pow(tmp1+tmp2, 1, N)
            B_bytes = B.to_bytes(128, 'big')
            
            # Recieve (I, Enc(A))
            response = conn.recv(I_len+128)
            decA_bytes = response[I_len: I_len+128]
            Enc_A = int.from_bytes(decA_bytes, 'big')
            print(f"Server: Received Enc(A) = {Enc_A}")

            # Decrpt A
            A = decrypt(Enc_A, server_d, server_N)
            print(f"Server: A = {A}")
            print( f"Server: B = {B}")

            # Send (s, B)
            clientdata = client_s + B_bytes
            conn.send(clientdata)

            # Compute u ≡ H(A||B) (mod N)
            A_bytes = A.to_bytes(128, 'big')
            hash_str = A_bytes + B_bytes
            d2 = digest256.copy()
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

            # Compute M1 test = H(A||B||Kclient)
            hash_str = A_bytes + B_bytes + ks_bytes
            d3 = digest256.copy()
            d3.update(hash_str)
            test_bytes = d3.finalize()

            M_1_bytes = conn.recv(1024)
            M_1 = int.from_bytes(M_1_bytes, 'big')
            print(f"Server: Received M_1 = {M_1}\n")

            if (M_1_bytes == test_bytes):
                print("Server: Negotiation successful.")
            else:
                print("Server: Negotiation unsuccessful, aborting.")
                return 0

            # Compute M2
            hash_str = A_bytes + M_1_bytes + ks_bytes
            d4 = digest256.copy()
            d4.update(hash_str)
            M_2 = d4.finalize()
            conn.send(M_2)

            print(f"Server: M_2 = {M_2}\n")
            print(f"Server: sending M_2 <{M_2}>\n")

            # Receive server_tag
            client_tag = conn.recv(2048)
            
            iv = client_tag[4:20]
            decrypt_text = client_tag[20:]

            hash_digest = hashes.Hash(hashes.SHA3_256(), BACKEND)
            tag2 = hash_digest.copy()
            tag2.update(ks_bytes)
            key_hash = tag2.finalize()

            # Use AES CBC mode to decrypt the cipherText
            cipher = Cipher(algorithms.AES(key_hash), modes.CBC(iv), BACKEND)
            decryptor = cipher.decryptor()
            byte_text = decryptor.update(decrypt_text) + decryptor.finalize()

            # Unad the decrypted text
            unpadder = padding.PKCS7(128).unpadder()
            unpadded_text = unpadder.update(byte_text) + unpadder.finalize()

            file_len = len(unpadded_text)-32
            byte_text = unpadded_text[:file_len]
            hash_file = unpadded_text[file_len:]

            hash_digest = hashes.Hash(hashes.SHA3_256(), BACKEND)
            tag2 = hash_digest.copy()
            tag2.update(byte_text)
            hash_test = tag2.finalize()

            if (hash_file == hash_test):
                with open(decrypted_filename, "wb") as fd:
                    fd.write(byte_text)            


if __name__ == "__main__":
    main(sys.argv)
