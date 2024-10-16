# Example simplified S-box for one round (2x4 S-box, simplified)
S_BOX = [
    [[14, 4, 13, 1], [2, 15, 11, 8]],
    [[3, 10, 6, 12], [5, 9, 0, 7]]
]

# Example Expansion Table for single round DES
EXPANSION_TABLE = [4, 1, 2, 3, 2, 3, 4, 1]

# Example Permutation Table for single round DES
PERMUTATION_TABLE = [2, 4, 3, 1]

# Function to perform XOR between two bit strings
def xor(bits1, bits2):
    return ''.join(['1' if bit1 != bit2 else '0' for bit1, bit2 in zip(bits1, bits2)])

# Function to perform expansion on the right half
def expand(bits):
    return ''.join([bits[i - 1] for i in EXPANSION_TABLE])

# Function to substitute using a simplified S-box
def substitute(expanded_half):
    if len(expanded_half) != 4:
        raise ValueError("Expanded half must be 4 bits for substitution.")
    
    row = int(expanded_half[0] + expanded_half[-1], 2)  # First and last bit to determine row
    col = int(expanded_half[1:3], 2)                    # Middle bits to determine column

    # Ensure row and column are within bounds for the S-box
    if row >= len(S_BOX) or col >= len(S_BOX[0][0]):
        raise IndexError("S-box index out of range")
    
    return format(S_BOX[0][row][col], '02b')  # Simplified S-box (2-bit output)

# Function to permute bits after substitution
def permute(bits):
    return ''.join([bits[i - 1] for i in PERMUTATION_TABLE])

# Function to perform one round of DES
def des_round(left, right, round_key):
    # Expand right half to 8 bits
    expanded_right = expand(right)
    # XOR with the round key
    xored = xor(expanded_right, round_key)
    # Substitute using S-box (make sure the input length is 4 bits after expansion)
    substituted = substitute(xored[:4])  # Only 4 bits are substituted in this simplified version
    # Permute the result
    permuted = permute(substituted)
    # XOR with the left half
    new_right = xor(left, permuted)
    return right, new_right

# Encryption function (Single Round)
def encrypt(plaintext, round_key):
    # Ensure that plaintext and round_key are both 8 bits
    if len(plaintext) != 8 or len(round_key) != 8:
        raise ValueError("Plaintext and round key must be 8 bits long.")
    
    # Split the plaintext into left and right halves (4 bits each)
    left = plaintext[:4]
    right = plaintext[4:]
    # Perform one round of DES
    left, right = des_round(left, right, round_key)
    # Return the result
    return left + right

# Decryption function (Single Round)
def decrypt(ciphertext, round_key):
    # Ensure that ciphertext and round_key are both 8 bits
    if len(ciphertext) != 8 or len(round_key) != 8:
        raise ValueError("Ciphertext and round key must be 8 bits long.")
    
    # Split the ciphertext into left and right halves (4 bits each)
    left = ciphertext[:4]
    right = ciphertext[4:]
    # Perform one round of DES (using same function but reverse the halves)
    right, left = des_round(left, right, round_key)
    # Return the result
    return left + right

if __name__ == "__main__":
    # Example 8-bit plaintext and round key
    plaintext = "11001010"  # 8-bit plaintext
    round_key = "10101010"  # 8-bit round key

    print(f"Original Plaintext: {plaintext}")

    # Encrypt the plaintext
    encrypted = encrypt(plaintext, round_key)
    print(f"Encrypted: {encrypted}")

    # Decrypt the ciphertext
    decrypted = decrypt(encrypted, round_key)
    print(f"Decrypted: {decrypted}")
