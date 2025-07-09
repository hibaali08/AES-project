from flask import Flask, render_template, request, send_file
from aes import encrypt_block, decrypt_block
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    encrypted = None
    decrypted = None

    if request.method == 'POST':
        if 'plaintext' in request.form:
            plaintext = request.form['plaintext']
            key_hex = request.form['key']
            key_bytes = bytes.fromhex(key_hex)
            plaintext_bytes = plaintext.encode()
            plaintext_int = int.from_bytes(plaintext_bytes.ljust(16, b'\0'), 'big')
            encrypted_int = encrypt_block(plaintext_int, key_bytes)
            encrypted = encrypted_int.to_bytes(16, 'big').hex()

        elif 'ciphertext' in request.form:
            ciphertext_hex = request.form['ciphertext']
            key_hex = request.form['key']
            key_bytes = bytes.fromhex(key_hex)
            ciphertext_int = int(ciphertext_hex, 16)
            decrypted_int = decrypt_block(ciphertext_int, key_bytes)
            decrypted_bytes = decrypted_int.to_bytes(16, 'big').rstrip(b'\0')
            decrypted = decrypted_bytes.decode(errors='ignore')

    return render_template('index.html', encrypted=encrypted, decrypted=decrypted)


@app.route('/encrypt-file', methods=['POST'])
def encrypt_file():
    file = request.files['file']
    key_hex = request.form['key']
    key_bytes = bytes.fromhex(key_hex)
    assert len(key_bytes) == 16, "Key must be 16 bytes"

    content = file.read().decode()
    content_bytes = content.encode()
    blocks = [content_bytes[i:i+16].ljust(16, b'\0') for i in range(0, len(content_bytes), 16)]

    encrypted_blocks = []
    for block in blocks:
        plaintext_int = int.from_bytes(block, 'big')
        encrypted_int = encrypt_block(plaintext_int, key_bytes)
        encrypted_blocks.append(encrypted_int.to_bytes(16, 'big'))

    encrypted_data = b''.join(encrypted_blocks)
    encrypted_path = 'encrypted_output.aes'
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)

    return send_file(encrypted_path, as_attachment=True)


@app.route('/decrypt-file', methods=['POST'])
def decrypt_file():
    file = request.files['file']
    key_hex = request.form['key']
    key_bytes = bytes.fromhex(key_hex)
    assert len(key_bytes) == 16, "Key must be 16 bytes"

    encrypted_data = file.read()
    blocks = [encrypted_data[i:i+16] for i in range(0, len(encrypted_data), 16)]

    decrypted_blocks = []
    for block in blocks:
        block_int = int.from_bytes(block, 'big')
        decrypted_int = decrypt_block(block_int, key_bytes)
        decrypted_block = decrypted_int.to_bytes(16, 'big')
        decrypted_blocks.append(decrypted_block)

    decrypted_data = b''.join(decrypted_blocks).rstrip(b'\0')
    decrypted_path = 'decrypted_output.txt'
    with open(decrypted_path, 'wb') as f:
        f.write(decrypted_data)

    return send_file(decrypted_path, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
