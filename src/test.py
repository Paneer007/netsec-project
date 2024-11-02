from dylithium_py.src.dilithium_py.dilithium import Dilithium5

SERVER_DILITHIUM_PUBLIC_KEY, SERVER_DILITHIUM_PRIVATE_KEY = Dilithium5.keygen()

with open("./certificates/server_dilithium_public_key.txt","wb") as f:
    f.write(SERVER_DILITHIUM_PUBLIC_KEY)

with open("./certificates/server_dilithium_public_key.txt","rb") as k:
    ALICE_PUBLIC_KEY = k.read()