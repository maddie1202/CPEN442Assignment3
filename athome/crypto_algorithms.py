import secrets
from base64 import b64decode, b64encode
import hashlib
import json
from Crypto.Cipher import AES

def from_b64str(s):
    return b64decode(s.encode())

def to_b64str(b):
    return b64encode(b).decode()

# key is bytes, returns bytes of length 256
def hash(key):
    return hashlib.sha256(key).digest()

# returns a base64 string
def generate_nonce():
    return to_b64str(secrets.token_bytes(16))

def encrypt(plaintext, key):
    plaintext_bytes = str.encode(plaintext, 'utf-16')
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    print(ciphertext)
    return encrypted_to_json(ciphertext, tag, cipher.nonce)

def decrypt(encrypted_json, key):
    ciphertext, tag, nonce = encrypted_from_json(encrypted_json)
    print(ciphertext)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext_bytes.decode('utf-16')

def encrypted_to_json(ciphertext, tag, nonce):
    return json.dumps({
        'ciphertext': to_b64str(ciphertext), 
        'tag': to_b64str(tag),
        'nonce': to_b64str(nonce)})

def encrypted_from_json(encrypted_json):
    encrypted = json.loads(encrypted_json)
    return (
        from_b64str(encrypted['ciphertext']),
        from_b64str(encrypted['tag']),
        from_b64str(encrypted['nonce'])
    )

# key = hash(b'8hSLISO4AyfztO3Ly6d8EQ==')

# encrypted = encrypt("Hello, World!", key)
# print(decrypt(encrypted, key))