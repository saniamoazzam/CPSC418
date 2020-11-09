# File creator: Sania Moazzam
# Run with: python3 TTP.py
# Description: waits for connection from server to send TTP_SIGNATURE and 
#           from client to send TTP RSA public key

from shared import *

def main():
    tmp = 0
    PORT = 31802

    # Generate RSA key pairs
    public_key, private_key = parameters()
    TTP_N = public_key[0]
    TTP_e = public_key[1]
    TTP_d = private_key[0]
    TTP_p = private_key[1]
    TTP_q = private_key[2]

    print(f"TTP: TTP_N = {TTP_N}")
    print(f"TTP: TTP_e = {TTP_e}")

    print(f"TTP: TTP_d = {TTP_d}")
    print(f"TTP: TTP_p = {TTP_p}")
    print(f"TTP: TTP_q = {TTP_q}\n")

    # Open TTP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((HOST, PORT))
            print('TTP listening...\n')
            
            while True:
                if tmp == 2:
                    break

                sock.listen()
                conn, addr = sock.accept()

                with conn:
                    # Receive REQUEST SIGN/KEY 
                    request = conn.recv(12)

                    if request.decode('utf-8') == "REQUEST SIGN":
                        print("TTP: Recieved 'REQUEST SIGN'")
                        data = conn.recv(2048)

                        # Process server name and public key 
                        length = data[:4]
                        S_len = int.from_bytes(length, 'big')
                        curr = S_len + 4
                        S = data[4: curr]
                        server_Nb = data[curr: curr+128]
                        server_eb = data[curr+128:curr+256]
                        server_N = int.from_bytes(server_Nb, 'big')
                        server_e = int.from_bytes(server_eb, 'big')
                        del data

                        print(f"TTP: Received len(S) = {S_len}")
                        print(f"TTP: Received S = '{S.decode('utf-8')}'")
                        print(f"TTP: Received Server_N = {server_N}")
                        print(f"TTP: Received Server_e = {server_e}\n")

                        print(f"TTP: S = '{S.decode('utf-8')}'")
                        print(f"TTP: Server_N = {server_N}")
                        print(f"TTP: Server_e = {server_e}\n")

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
                        
                        # Compute RSA sign on value
                        TTP_SIG = signature(tt1_red, TTP_d, TTP_N)
                        print(f"TTP: TTP_SIG = {TTP_SIG}")
                        SIG_concat = TTP_N.to_bytes(128, 'big') + TTP_SIG.to_bytes(128, 'big')

                        print(f"TTP: Sending TTP_N <{hex(TTP_N)}>\n")
                        print(f"TTP: Sending TTP_SIG <{hex(TTP_SIG)}>")

                        conn.send(SIG_concat)

                    if request.decode('utf-8') == "REQUEST KEY":
                        print("TTP: Recieved 'REQUEST KEY'")

                        # Send TTP public key
                        e_bytes = TTP_e.to_bytes(128, 'big')
                        N_bytes = TTP_N.to_bytes(128, 'big')
                        client_data = N_bytes + e_bytes

                        print(f"TTP: Sending TTP_N = {TTP_N}")
                        print(f"TTP: Sending TTP_e = {TTP_e}")
                        conn.send(client_data)

                tmp = tmp + 1
                del request


if __name__ == "__main__":
    main()