"""
 AES-128 Asymmetric Encryption Standard Algorithm Implementation in Python

 This file implements core components of AES-128 algorithm using 128-bit keys.
 This includes the S-box, SubBytes transformation, ShiftRows, MixColumns and AddRoundKey 
 transformations as per the AES specification.

 Author: Hiba Ali
 Project- DRDO AES Encryption Implementation
"""

# S-BOX (Substitution Box)
"""
AES defines a 16X16 matrix of byte values, called an S-box,
This S-box contains a permutation of 256 8-bit values. It performs a non-linear 
byte substitution based on a precomputed 16x16 lookup table.
"""
S_BOX=[
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

InvS_BOX=[
     0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

RCON=(
     0x00,  # Rcon[0] is never used
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
)

#HELPER FUNCTIONS
def rot_word(word):
    """
    Rotates a 4-byte word to the left (e.g., [0x09, 0xcf, 0x4f, 0x3c] → [0xcf, 0x4f, 0x3c, 0x09])
    """
    return word[1:] + word[:1]

def sub_word(word):
    """
    Applies the S-box substitution to each byte in a 4-byte word.
    """
    return [S_BOX[b] for b in word]



#KEY EXPANSION
"""
    Expands a 16-byte AES key into 44 4-byte round key words (176 bytes total).
    
    Args:
        cipher_key (list of 16 ints): The original AES key
    
    Returns:
        list of 44 words (each a list of 4 bytes)
"""
def key_expansion(cipher_key):
    # Accepts bytes or list of 16 integers
    if isinstance(cipher_key, bytes):
        assert len(cipher_key) == 16, "Key must be 16 bytes (128 bits)"
        cipher_key = list(cipher_key)
    elif isinstance(cipher_key, list):
        assert len(cipher_key) == 16, "Key must be 16 bytes (128 bits)"
    else:
        raise TypeError("cipher_key must be bytes or list of 16 ints")

    # Split into 4 words (4 bytes each)
    cipher_key_words = [cipher_key[i:i+4] for i in range(0, 16, 4)]

    key_schedule = cipher_key_words.copy()
    for i in range(4, 44):  
        temp = key_schedule[i - 1][:]
        if i % 4 == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= RCON[i // 4]
        word = [temp[j] ^ key_schedule[i - 4][j] for j in range(4)]
        key_schedule.append(word)

    return key_schedule


#TESTING
"""cipher_key = [
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x6c, 0x6f,
    0x15, 0x88, 0x09, 0xcf
]

expanded_keys = key_expansion(cipher_key)

# Print all round keys
for i in range(11):
    round_key = expanded_keys[4*i : 4*(i+1)]
    print(f"Round {i}: {round_key}")"""

#STATE MATRIX FUNCTIONS

"""
    Converts a 128-bit integer into a 4x4 state matrix filled column-wise.
    Each element in the matrix is a byte (8-bit int).
    """
def bytes_2_matrix(text):
    matrix = [[0] * 4 for _ in range(4)]
    for i in range(16):
        byte = (text >> (8 * (15 - i))) & 0xFF
        row = i % 4
        col = i // 4
        matrix[row][col] = byte
    return matrix


"""
    Converts a 4x4 state matrix back into a 128-bit integer.
    The matrix  is read column-wise.
    """
def matrix_2_bytes(matrix):
     text = 0
     for col in range(4):
        for row in range(4):
            byte = matrix[row][col]
            shift = 8 * (15 - (4 * col + row))
            text |= (byte << shift)
     return text

def words_2_matrix(words):
    """Converts 4 words (16 bytes) into a 4x4 matrix column-wise."""
    matrix = [[0] * 4 for _ in range(4)]
    for i in range(4):  # columns
        for j in range(4):  # rows
            matrix[j][i] = words[i][j]
    return matrix


#TESTING
"""# 128-bit plaintext represented as an integer
plaintext = 0x3243f6a8885a308d313198a2e0370734

# Convert to matrix
state = bytes_2_matrix(plaintext)
print("Matrix:")
for row in state:
    print(row)

# Convert back to int
reconverted = matrix_2_bytes(state)"""


#CORE ENCRYPTION STEPS
def add_round_key(state, round_key):
    """
    XORs the state matrix with the round key (both 4x4 byte matrices).
    """
    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]


def sub_bytes(state):
    """
    Applies the S-box substitution to each byte in the state matrix.
    """
    for row in range(4):
        for col in range(4):
            byte = state[row][col]
            state[row][col] = S_BOX[byte]


def shift_rows(state):
    """
    Performs row-wise circular left shift on the state matrix:
    Row 0 → No shift
    Row 1 → Shift left by 1
    Row 2 → Shift left by 2
    Row 3 → Shift left by 3
    """
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]


# Predefined multiplication helper for GF(2^8)
def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)

def mix_single_column(col):
    """
    Mixes one column using the AES MixColumns matrix.
    """
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u = col[0]
    col[0] ^= t ^ xtime(col[0] ^ col[1])
    col[1] ^= t ^ xtime(col[1] ^ col[2])
    col[2] ^= t ^ xtime(col[2] ^ col[3])
    col[3] ^= t ^ xtime(col[3] ^ u)

def mix_columns(state):
    """
    Applies the MixColumns transformation to the state.
    Each column is multiplied in GF(2^8) with the fixed AES matrix.
    """
    for col in range(4):
        column = [state[row][col] for row in range(4)]
        mix_single_column(column)
        for row in range(4):
            state[row][col] = column[row]


#CORE DECRYPTION STEPS
def inv_shift_rows(state):
    """
    Reverses the ShiftRows step by performing right circular shifts on each row.
    Row 0: No shift
    Row 1: Right shift by 1
    Row 2: Right shift by 2
    Row 3: Right shift by 3
    """
    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]


def inv_sub_bytes(state):
    """
    Applies the inverse S-box substitution to each byte in the state matrix.
    """
    for row in range(4):
        for col in range(4):
            byte = state[row][col]
            state[row][col] = InvS_BOX[byte]




def mul_by_09(x):
    return xtime(xtime(xtime(x))) ^ x

def mul_by_0b(x):
    return xtime(xtime(xtime(x)) ^ x) ^ x

def mul_by_0d(x):
    return xtime(xtime(xtime(x) ^ x)) ^ x

def mul_by_0e(x):
    return xtime(xtime(xtime(x) ^ x) ^ x)

def inv_mix_columns(state):
    """
    Applies the inverse MixColumns transformation to each column of the state.
    """
    for col in range(4):
        a = [state[row][col] for row in range(4)]

        state[0][col] = (
            mul_by_0e(a[0]) ^ mul_by_0b(a[1]) ^
            mul_by_0d(a[2]) ^ mul_by_09(a[3])
        )
        state[1][col] = (
            mul_by_09(a[0]) ^ mul_by_0e(a[1]) ^
            mul_by_0b(a[2]) ^ mul_by_0d(a[3])
        )
        state[2][col] = (
            mul_by_0d(a[0]) ^ mul_by_09(a[1]) ^
            mul_by_0e(a[2]) ^ mul_by_0b(a[3])
        )
        state[3][col] = (
            mul_by_0b(a[0]) ^ mul_by_0d(a[1]) ^
            mul_by_09(a[2]) ^ mul_by_0e(a[3])
        )

def bytes_to_matrix_key(key_bytes):
    return [list(key_bytes[i:i+4]) for i in range(0, 16, 4)]

#FINAL FUNCTIONS

def encrypt_block(plaintext_block, cipher_key):
    state = bytes_2_matrix(plaintext_block)
    round_keys = key_expansion(cipher_key)

    # Initial AddRoundKey
    add_round_key(state, words_2_matrix(round_keys[:4]))

    # Rounds 1–9
    for i in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, words_2_matrix(round_keys[4*i: 4*(i+1)]))

    # Final Round (no MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, words_2_matrix(round_keys[40:]))

    return matrix_2_bytes(state)



def decrypt_block(ciphertext_block, cipher_key):
    state = bytes_2_matrix(ciphertext_block)
    round_keys = key_expansion(cipher_key)

    # Initial AddRoundKey
    add_round_key(state, words_2_matrix(round_keys[40:]))

    # Rounds 9–1
    for i in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, words_2_matrix(round_keys[4*i: 4*(i+1)]))
        inv_mix_columns(state)

    # Final Round (no InvMixColumns)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, words_2_matrix(round_keys[:4]))

    return matrix_2_bytes(state)


plaintext = 0x3243f6a8885a308d313198a2e0370734
cipher_key = bytes([
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x6c, 0x6f,
    0x15, 0x88, 0x09, 0xcf
])

ciphertext = encrypt_block(plaintext, cipher_key)
print(f"Encrypted: {hex(ciphertext)}")

decrypted = decrypt_block(ciphertext, cipher_key)
print(f"Decrypted: {hex(decrypted)}")

