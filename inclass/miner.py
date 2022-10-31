from hashlib import sha256
import random
import string
from datetime import datetime
import base64

hash_of_preceding_coin = 'a9c1ae3f4fc29d0be9113a42090a5ef9fdef93f5ec4777a008873972e60bb532'
id_of_miner = sha256('42'.encode('ascii')).hexdigest()

# bytes([46, 46, 46].hex() for converting to a hex string
# bytes.fromhex('string') for converting from a hex string

def compute_hash_hex(coin_blob):
    m = sha256()
    m.update(bytes('CPEN 442 Coin' + '2022' + hash_of_preceding_coin + coin_blob + id_of_miner, 'ascii'))
    return m.hexdigest()

def hash_starts_with_n_zeros(hash, n):
    return hash[0:n] == ('0' * n)

def mine_with_n_zeros(n):
    begin = datetime.now()
    while True:
        coin_blob = ''.join(random.choices(string.ascii_letters + string.digits, k=50))
        hexhash = compute_hash_hex(coin_blob)
        if hash_starts_with_n_zeros(hexhash, n):
            print(f"Miner id: {id_of_miner}")
            print(base64.b64encode(bytes(coin_blob, 'ascii')))
            end = datetime.now()
            return end - begin

print("n=4")
print(mine_with_n_zeros(4))
print("n=5")
print(mine_with_n_zeros(5))
print("n=6")
print(mine_with_n_zeros(6))
print("n=7")
print(mine_with_n_zeros(7))