
# Caesar Cipher Encryption
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted_text += char  # Non-alphabetical characters are not shifted, they are remained same
    return encrypted_text


# Caesar Cipher Decryption
def caesar_decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            decrypted_text += chr((ord(char) - shift_base - shift) % 26 + shift_base)
        else:
            decrypted_text += char  # Non-alphabetical characters are not shifted, they are remained same
    return decrypted_text


message = "Hello World"
print(f"Original Message: {message}")

shift_value = 3

# Encrypt the message
encrypted_message = caesar_encrypt(message, shift_value)
print(f"Encrypted: {encrypted_message}")

# Decrypt the message
decrypted_message = caesar_decrypt(encrypted_message, shift_value)
print(f"Decrypted: {decrypted_message}")
