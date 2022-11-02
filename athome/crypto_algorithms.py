import secrets
from base64 import b64decode, b64encode
import hashlib
import json
from Crypto.Cipher import AES

def get_p():
    s = open('diffiehellman/p.txt').read()
    return int_from_bytes(bytes.fromhex(s))

def get_g():
    s = open('diffiehellman/g.txt').read()
    return int_from_bytes(bytes.fromhex(s))

def from_b64str(s):
    return b64decode(s.encode())

def to_b64str(b):
    return b64encode(b).decode()

# key is bytes, returns bytes of length 256
def hash(key):
    return hashlib.sha256(key).digest()

def hash_str(s) -> bytes:
    return hash(str.encode(s))

def generate_nonce(n_bytes) -> bytes:
    return secrets.token_bytes(n_bytes)

# returns a base64 string
def generate_nonce_str(n_bytes) -> str:
    return to_b64str(generate_nonce(n_bytes))

def generate_nonce_int(n_bytes) -> int:
    return int.from_bytes(generate_nonce(n_bytes), byteorder='big')

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')
    
def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')

def encrypt(plaintext: str , key: bytes):
    assert(key != None and key != b'')
    plaintext_bytes = str.encode(plaintext, 'utf-16')
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return encrypted_to_json(ciphertext, tag, cipher.nonce)

def decrypt(encrypted_json, key):
    ciphertext, tag, nonce = encrypted_from_json(encrypted_json)
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