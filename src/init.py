from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from dylithium_py.src.dilithium_py.dilithium import Dilithium5

# This module converts binary data to hexadecimal
from binascii import hexlify


SERVER_PRIVATE_KEY = RSA.generate(4096*2)
SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.publickey()

BOB_PRIVATE_KEY = RSA.generate(1024)
BOB_PUBLIC_KEY = BOB_PRIVATE_KEY.publickey()

ALICE_PRIVATE_KEY = RSA.generate(1024)
ALICE_PUBLIC_KEY = ALICE_PRIVATE_KEY.publickey()

SERVER_DILITHIUM_PUBLIC_KEY, SERVER_DILITHIUM_PRIVATE_KEY = Dilithium5.keygen()

with open("./certificates/server_private_key.pem","wb") as f:
    f.write(SERVER_PRIVATE_KEY.export_key())

with open("./certificates/server_public_key.pem","wb") as f:
    f.write(SERVER_PUBLIC_KEY.export_key())

with open("./certificates/server_dilithium_public_key.crt","wb") as f:
    f.write(SERVER_DILITHIUM_PUBLIC_KEY)

with open("./certificates/server_dilithium_private_key.crt","wb") as f:
    f.write(SERVER_DILITHIUM_PRIVATE_KEY)

with open("./certificates/alice_private_key.pem","wb") as f:
    f.write(ALICE_PRIVATE_KEY.export_key())

with open("./certificates/alice_public_key.pem","wb") as f:
    f.write(ALICE_PUBLIC_KEY.export_key())

with open("./certificates/bob_private_key.pem","wb") as f:
    f.write(BOB_PRIVATE_KEY.export_key())

with open("./certificates/bob_public_key.pem","wb") as f:
    f.write(BOB_PUBLIC_KEY.export_key())
