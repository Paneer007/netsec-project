from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None
SERVER_DILITHIUM_PRIVATE_KEY = None
SERVER_DILITHIUM_PUBLIC_KEY = None

with open("./certificates/server_private_key.pem","r") as k:
    SERVER_PRIVATE_KEY = RSA.importKey(k.read())

with open("./certificates/server_public_key.pem","r") as k:
    SERVER_PUBLIC_KEY = RSA.import_key(k.read())
    
with open("./certificates/server_dilithium_private_key.crt","rb") as k:
    SERVER_DILITHIUM_PRIVATE_KEY = k.read()

with open("./certificates/server_dilithium_public_key.crt","rb") as k:
    SERVER_DILITHIUM_PUBLIC_KEY = k.read()

SERVER_CIPHER_RSA = PKCS1_OAEP.new(SERVER_PUBLIC_KEY)
SERVER_DECIPHER_RSA = PKCS1_OAEP.new(SERVER_PRIVATE_KEY)

data_to_encrypt = b"Hello, this is a message to be encrypted."
encrypted = SERVER_CIPHER_RSA.encrypt(data_to_encrypt)

decrypted = SERVER_DECIPHER_RSA.decrypt(encrypted)
