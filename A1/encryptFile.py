# File creator: Sania Moazzam
# Run with: python encryptFile.py [plainText file] [tampered filename] [password]

# Description: Takes in a cipherText file, iterates over date range (1984 - today's date) 
#               as possible password and decrypts the cipherText file. Decryption is done
#               by computing a hash on the possible password and the AES-CBC mode decryptor
#               with a random iv. If there is 'FOXHOUND' in the decrypted text, the function
#               breaks out of the loop and outputs the found password. The iv is removed from
#               the decrypted text and it is unpadded and decoded into utf-8 format. The program 
#               checks if 'CODE-RED' is found in the plainText, modifies it to 'CODE-BLUE' if
#               necessary and outputs if the plainText was modified or not.

# Output: a cipherText file containing binary data, it's name is passed in as the second argumet

import os
import sys
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def main(argv):

    # Read in all three arguments
    with open(argv[1], "r") as fd:
        plain_text = fd.read()

    tampered_filename = argv[2]
    password = argv[3]

    # Convert plaintext to bytes
    byte_text = bytes(plain_text.encode())
    # Create hash tag with SHA1
    hash_digest = hashes.Hash(hashes.SHA1(), BACKEND)

    # Create extended byte array
    tag1 = hash_digest.copy()
    tag1.update(byte_text)
    byte_hash = byte_text + tag1.finalize()

    # Create encryption key 
    tag2 = hash_digest.copy()
    tag2.update(password.encode())
    encrypt_key = tag2.finalize()[0:16]

    # Generate IV and write to file
    iv = os.urandom(16)
    with open(tampered_filename, "wb") as fd:
        fd.write(iv)

    # Pads B_hash if block size < 16
    size = len(byte_hash)
    if size % 16 != 0:
        padder = padding.PKCS7(128).padder()
        padded_byte_hash = padder.update(byte_hash) + padder.finalize()
    else:
        padded_byte_hash = byte_hash

    # Encrypt using AES-128-CBC
    cipher = Cipher(algorithms.AES(encrypt_key), modes.CBC(iv), BACKEND)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_byte_hash) + encryptor.finalize()
    with open(tampered_filename, "ab") as fd:
        fd.write(cipher_text)


if __name__ == "__main__":
    BACKEND = default_backend()
    main(sys.argv)