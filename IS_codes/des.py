from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# Function to encrypt data using DES
def des_encrypt(plaintext, key):
    # Ensure the key is 64-bits long (DES uses a 64-bits key)
    des = DES.new(key, DES.MODE_ECB)
    # Pad the plaintext to be a multiple of 8 bytes
    padded_text = pad(plaintext.encode('utf-8'), DES.block_size)  # Corrected here
    encrypted_text = des.encrypt(padded_text)
    return encrypted_text


# Function to decrypt data using DES
def des_decrypt(ciphertext, key):
    des = DES.new(key, DES.MODE_ECB)
    decrypted_text = des.decrypt(ciphertext)
    # Unpad the decrypted text to retrieve the original plaintext
    return unpad(decrypted_text, DES.block_size).decode('utf-8')


if __name__ == "__main__":
    key = get_random_bytes(8)  # Generate a random 8-byte (64-bit) key
    plaintext = "Hello, World!"
    print(f"Original Message: {plaintext}")

    # Encrypt the plaintext
    encrypted = des_encrypt(plaintext, key)
    print(f"Encrypted: {encrypted}")

    # Decrypt the ciphertext
    decrypted = des_decrypt(encrypted, key)
    print(f"Decrypted: {decrypted}")
