from aes import encrypt_block, decrypt_block  # Adjust if your function names differ
import binascii

# Convert hex string (e.g. "6bc1...") to 16-byte bytes
def hex_to_bytes(hex_str):
    return binascii.unhexlify(hex_str)

# Convert hex string to int (for plaintext and ciphertext)
def hex_to_int(hex_str):
    return int(hex_str, 16)

def run_test_case(name, key_hex, plaintext_hex, expected_ciphertext_hex):
    key = hex_to_bytes(key_hex)  # ✔ 16-byte key
    plaintext = hex_to_int(plaintext_hex)  # ✔ 128-bit int
    expected_ciphertext = hex_to_int(expected_ciphertext_hex)  # ✔ 128-bit int

    ciphertext = encrypt_block(plaintext, key)

    if ciphertext == expected_ciphertext:
        print(f"[✓] {name}: Encryption PASSED")
    else:
        print(f"[✗] {name}: Encryption FAILED")
        print("Expected:", hex(expected_ciphertext))
        print("Got     :", hex(ciphertext))

    decrypted = decrypt_block(ciphertext, key)
    if decrypted == plaintext:
        print(f"[✓] {name}: Decryption PASSED")
    else:
        print(f"[✗] {name}: Decryption FAILED")
        print("Expected:", hex(plaintext))
        print("Got     :", hex(decrypted))

# Run the test
run_test_case(
    name="NIST AES-128 ECB Test 1",
    key_hex="2b7e151628aed2a6abf7158809cf4f3c",
    plaintext_hex="6bc1bee22e409f96e93d7e117393172a",
    expected_ciphertext_hex="3ad77bb40d7a3660a89ecaf32466ef97"
)