# File creator: Sania Moazzam
# Run with: python3 shared.py
# Description: consists of RSA methods and generates safe prime functions used by the other files

import os
import sys
import sympy
import random
import socket
import secrets
from math import gcd
from sympy.core.numbers import mod_inverse
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = "127.0.4.18"
BACKEND = default_backend()
digest512 = hashes.Hash(hashes.SHA3_512(), BACKEND)

def safeprime():
    bits=512

    maximum = 1 << bits
    q = secrets.randbits(bits-1) | (1 << (bits-2))   

    if (q != 2):   # rule out even numbers, excluding 2
        q |= 1

    while True:    #check if entire range has been exhausted

        if sympy.isprime( q ):
            cand = (q<<1) + 1
            if sympy.isprime( cand ):
                return cand

        if q == 2:      # rule out even numbers, special-casing 2
            q = 3
        else:
            q += 2

        if q >= maximum:
            q = 1 << (bits-2)


def parameters():
    # Initialize variables to 0
    q = 0
    p = 0
    e = 0

    # Generate 512 bit prime q
    q = safeprime()

    # Generate 512 bit prime p
    p = safeprime()

    # Calculate N and eulers number
    N = p*q
    euler = (p-1)*(q-1)

    # Calculate e
    while (gcd(e, euler) != 1):
        e = random.randrange(1, euler)

    # Solve linear congruence
    d = mod_inverse(e, euler)
    #d = modInv(e, euler)

    # Gen public key pair
    public_key = (N, e)

    # Gen private key pair
    private_key = (d, p, q)

    return (public_key, private_key)


def encrypt(M, e, N):
    C = pow(M, e, N)
    return C


def decrypt(C, d, N):
    M = pow(C, d, N)
    return M


def signature(M, d, N):
    #d1 = digest512.copy()
    #d1.update(M)
    #h = int.from_bytes(d1.finalize(), 'big')
    sign = pow(M, d, N)
    return sign


def verification(sign, M, e, N):
    #d2 = digest512.copy()
    #d2.update(M)
    #msg_hash = int.from_bytes(d2.finalize(), 'big')

    sign_int = int.from_bytes(sign, 'big')
    signature_hash = pow(sign_int, e, N)
    
    if M == signature_hash:
        return True
    else:
        return False