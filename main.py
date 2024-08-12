from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import hashlib
import base64

def hash_keyword(keyword):
    return hashlib.sha256(keyword.encode()).hexdigest()

def pad(data):
    return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

def encrypt(data, key):
    data = pad(data)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(data)
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])
    return decrypted_data.rstrip(b"\0").decode('utf-8')

password = "mysecretpassword"
salt = get_random_bytes(16)
key = PBKDF2(password, salt, dkLen=32)

redis_store = {}

data = "Very important information"
keywords = ["sensitive", "information"]

encrypted_data = encrypt(data.encode(), key)

redis_store['data'] = encrypted_data

for keyword in keywords:
    redis_store[hash_keyword(keyword)] = 'data'

def search_encrypted_data(search_keyword):
    hashed_keyword = hash_keyword(search_keyword)
    data_key = redis_store.get(hashed_keyword)
    if data_key:
        encrypted_data = redis_store.get(data_key)
        if encrypted_data:
            decrypted_data = decrypt(encrypted_data, key)
            return decrypted_data
    return None

search_keyword = "sensitive"
found_data = search_encrypted_data(search_keyword)

print(f"Data found for keyword '{search_keyword}': {found_data}")