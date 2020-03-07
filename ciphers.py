from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

def create_rsa_key_pair():
    key = RSA.generate(2048)
    private = key.export_key().decode("utf-8")
    public = key.publickey().exportKey().decode("utf-8")
    return (private, public)

def encrypt_aes(message):
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_CBC, key[:16])
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    cypher_text = b64encode(ct_bytes).decode('utf-8')
    return (key, cypher_text)

def decrypt_aes(key, encoded):
    iv = key[:16]
    cypher_text = b64decode(encoded)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = unpad(cipher.decrypt(cypher_text), AES.block_size)
    return message

def decrypt_rsa(private_key, encoded):
    cypher_text = b64decode(encoded)
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(cypher_text)

def decrypt_json(private_key, encoded):
    # print('encode message length', len(encoded))
    key_len = int(encoded[:3], 16) # hex
    # print('encrypted aes_key length', key_len)
    encrypted_aes = encoded[3:key_len + 3]
    # print('encrypted aes_key', encrypted_aes)
    aes_key = decrypt_rsa(private_key, encrypted_aes)
    # print('decrypted aes_key', b64encode(aes_key))
    encoded_cypher_text = encoded[key_len + 3:]
    # print('encoded_cypher_text', encoded_cypher_text)
    # print('encoded_cypher_text length', len(encoded_cypher_text))
    message = decrypt_aes(aes_key, encoded_cypher_text)
    # print('message', message)
    return message