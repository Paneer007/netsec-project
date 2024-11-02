import socket
from common import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import pickle
import socketserver
import sys


HOST, PORT = "localhost", 9998
ALICE_PORT = 9995


ALICE_PUBLIC_KEY = None
ALICE_PRIVATE_KEY = None

with open("./certificates/alice_private_key.pem","r") as k:
    ALICE_PRIVATE_KEY = RSA.importKey(k.read())

with open("./certificates/alice_public_key.pem","r") as k:
    ALICE_PUBLIC_KEY = RSA.importKey(k.read())

ALICE_DECIPHER_RSA = PKCS1_OAEP.new(ALICE_PRIVATE_KEY)

BOB_PUBLIC_KEY = None
BOB_CIPHER_RSA = None 


class MyUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        encrypted_data = self.request[0].strip()
        data = ALICE_DECIPHER_RSA.decrypt(encrypted_data)
        # data = encrypted_data
        socket = self.request[1]
        print("{} wrote:".format(self.client_address[0]))
        usr_data = input("> ")
        data = BOB_CIPHER_RSA.encrypt(usr_data.encode())
        socket.sendto(data,self.client_address)

def recvall(sock):
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            break
    return data

def check_valid_certificate(ds):
    body = ds.certificate_body
    data = pickle.dumps(body)
    hash = hashlib.sha256(data).digest()
    val_bytes = bytearray(hash)
    temp = ''.join(['%02x' % byte for byte in val_bytes])
    res = SERVER_DECIPHER_RSA.decrypt(ds.certificate_signature)
    temp = temp.encode()
    return temp == res

def get_bob_public_key():
    message = b"get_certificate_bob"
    data = SERVER_CIPHER_RSA.encrypt(message)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(data)
        received = recvall(sock)
        ds = pickle.loads(received)
        if not check_valid_certificate(ds):
            print("Invalid Certificate !!!")
            exit(0)
        return RSA.import_key(ds.certificate_body.subject_public_key)

def get_message():
    global BOB_PUBLIC_KEY
    global BOB_CIPHER_RSA
    BOB_PUBLIC_KEY = get_bob_public_key()
    BOB_CIPHER_RSA = PKCS1_OAEP.new(BOB_PUBLIC_KEY)
    
    with socketserver.UDPServer((HOST, ALICE_PORT), MyUDPHandler) as server:
        server.serve_forever()

def cli_loop():
    while(True):
        print("1- Receive Message from Bob")
        print("2- Exit")
        user_input = int(input("Enter Option: "))
        if user_input == 1:
            get_message()
        elif user_input == 2:
            print("Program over")
            exit(0)
        else:
            print("Enter Valid Input")

def create_certificate():
    message = b"create_certificate_alice " + ALICE_PUBLIC_KEY.export_key("OpenSSH")
    data = SERVER_CIPHER_RSA.encrypt(message)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(data)
        received = str(sock.recv(1024), "utf-8")


def cli():
    print("Alice logged in")
    create_certificate()
    cli_loop()

if __name__ == "__main__":
    cli()