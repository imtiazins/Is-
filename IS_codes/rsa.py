import math
import random as rd
import cmath

def removeSpaces(text):
    text = text.replace(" ", "")
    return text

def toUpperCase(text):
	return text.upper()

def gcd(a, b): #calculates gcd
    while b != 0:
        a, b = b, a % b
    return a

def multi_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m     #integer division
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return (x1 + m0) if (x1 < 0) else x1

def is_prime(num):
    if num <= 1:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    elif p == q:
        raise ValueError("p and q cannot be equal.")

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = rd.randrange(1, phi_n)
    g = gcd(e, phi_n)
    while g != 1:
        e = rd.randrange(1, phi_n)
        g = gcd(e, phi_n)

    d = multi_inverse(e, phi_n)

    return ((e, n), (d, n))

def rsa_encrypt(public_key, plaintext):
    e, n = public_key
    cipher = [pow(ord(char), e, n) for char in plaintext]
    return cipher

def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    plain = [chr(pow(char, d, n)) for char in ciphertext]
    return ''.join(plain)


if __name__ == '__main__':
    
    p = 7
    q = 13
    public_key, private_key = generate_keypair(p, q)

    message="That is awesome"
    print("Original message:", message)

    message = removeSpaces(message)
    message = toUpperCase(message)

    encrypted_message = rsa_encrypt(public_key, message)
    print("Encrypted message:", ' - '.join(str(x) for x in encrypted_message))

    decrypted_message = rsa_decrypt(private_key, encrypted_message)
    print("Decrypted message:", decrypted_message)
