# File creator: Sania Moazzam
# Run with: python modifyFile.py [cipherText file]

# Description: Converts plainText to bytes object. Computes a SHA1 hash
#            on the bytes object and concatenates it to the bytes object.
#           Computes a SHA1 hash on the password provided and makes it 16 
#           bytes. Pads the concatenated byte object if necessary using PKCS7.
#	        Generates a random iv value and encrypts the (padded) concatenated 
#           byte object with AES-128-CBC protocol. Writes encrypted text to a cipherText file.

# Output: the password 
#         tells you if the input file was modified or not

import os
import sys
import datetime as dt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def find_password(cipher_text):

    # Dates ranging from 1984 to today's date
    start_date = dt.date(1984, 1, 1)
    end_date = dt.date.today()
    day_delta = dt.timedelta(days=1)
    
    for i in range((end_date - start_date).days):
        # Convert date to appropriate format (YYYYMMDD)
        date_obj = start_date + i*day_delta
        curr_date = date_obj.strftime('%Y%m%d')

        # Calculate temp hash with date
        tag = hashes.Hash(hashes.SHA1(), BACKEND)
        tag.update(curr_date.encode())
        encrypt_key = tag.finalize()[0:16]

        # Use AES CBC mode to decrypt the cipherText
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(encrypt_key), modes.CBC(iv), BACKEND)
        decryptor = cipher.decryptor()
        decrypt_text = decryptor.update(cipher_text) + decryptor.finalize()

        if b'FOXHOUND' in decrypt_text:
            password = curr_date
            break

    print(f"The password is: {password}")
    return decrypt_text


def main(argv):

    # Read in cipher_text file
    with open(argv[1], "rb") as fd:
        cipher_text = fd.read()

    # Find password function
    decrypt_text = find_password(cipher_text)
    # Remove IV (which is 16 bytes) from decrypted text
    decrypt_text = decrypt_text[16:len(decrypt_text)]

    # Unpad the decrypted text
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_byte_text = unpadder.update(decrypt_text) + unpadder.finalize()

    # SHA1 hash tag is always 20 bytes
    length = len(unpadded_byte_text) - 20 
    byte_text = unpadded_byte_text[:length]
    plain_text = byte_text.decode()

    if 'CODE-RED' in plain_text:
        changed_text = plain_text.replace('CODE-RED', 'CODE-BLUE')
        with open("modified-plainText.txt", "w") as fd:
            fd.write(changed_text)

        print(f"\n{argv[1]} content was modified\nRun encryptFile.py on 'modified-plainText'\n")
    else:
        print(f"\n{argv[1]} did not contain 'CODE-RED' hence it was NOT modified\n")
 

if __name__ == "__main__":
    BACKEND = default_backend()
    main(sys.argv)
