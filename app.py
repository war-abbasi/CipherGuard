from flask import Flask, request, jsonify, send_from_directory
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from os import urandom
import bcrypt

app = Flask(__name__)

# Function to hash a password
def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

# Function to verify a password
def verify_password(hashed: bytes, password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# AES Cipher class
class AESCipher:
    def __init__(self, key: bytes):
        self.key = key
        self.backend = default_backend()

    def encrypt(self, plaintext: str) -> bytes:
        iv = urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted = iv + encryptor.update(plaintext.encode()) + encryptor.finalize()
        return encrypted

    def decrypt(self, encrypted: bytes) -> str:
        iv = encrypted[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted[16:]) + decryptor.finalize()
        return decrypted.decode()

# RSA Cipher class
class RSACipher:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, plaintext: str) -> bytes:
        encrypted = self.public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt(self, encrypted: bytes) -> str:
        decrypted = self.private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()

# Custom encryption function that replaces vowels with their phonetic equivalents
def custom_encrypt(plaintext: str) -> str:
    phonetics = {'a': 'alpha', 'e': 'echo', 'i': 'india', 'o': 'oscar', 'u': 'uniform',
                 'A': 'Alpha', 'E': 'Echo', 'I': 'India', 'O': 'Oscar', 'U': 'Uniform'}
    encrypted = ''.join(phonetics.get(char, char) for char in plaintext)
    return encrypted

# Custom decryption function that reverses the phonetic replacements
def custom_decrypt(encrypted: str) -> str:
    phonetics = {'alpha': 'a', 'echo': 'e', 'india': 'i', 'oscar': 'o', 'uniform': 'u',
                 'Alpha': 'A', 'Echo': 'E', 'India': 'I', 'Oscar': 'O', 'Uniform': 'U'}
    decrypted = encrypted
    for phonetic, vowel in phonetics.items():
        decrypted = decrypted.replace(phonetic, vowel)
    return decrypted

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    password = data.get('password')
    message = data.get('message')
    algo = data.get('algo')

    if (algo == 'aes'):
        key = urandom(32)
        aes_cipher = AESCipher(key)
        encrypted_message = aes_cipher.encrypt(message).hex()
    elif (algo == 'rsa'):
        rsa_cipher = RSACipher()
        encrypted_message = rsa_cipher.encrypt(message).hex()
    elif (algo == 'custom'):
        encrypted_message = custom_encrypt(message)
    else:
        return jsonify({'error': 'Invalid algorithm'}), 400

    return jsonify({'encrypted_message': encrypted_message})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    password = data.get('password')
    encrypted_message = data.get('encrypted_message')
    algo = data.get('algo')

    if (algo == 'aes'):
        key = urandom(32)
        aes_cipher = AESCipher(key)
        decrypted_message = aes_cipher.decrypt(bytes.fromhex(encrypted_message))
    elif (algo == 'rsa'):
        rsa_cipher = RSACipher()
        decrypted_message = rsa_cipher.decrypt(bytes.fromhex(encrypted_message))
    elif (algo == 'custom'):
        decrypted_message = custom_decrypt(encrypted_message)
    else:
        return jsonify({'error': 'Invalid algorithm'}), 400

    return jsonify({'decrypted_message': decrypted_message})

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

if __name__ == '__main__':
    app.run(debug=True)
