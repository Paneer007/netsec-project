import socket
from common import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import pickle
import socketserver
import sys
from dylithium_py.src.dilithium_py.dilithium import Dilithium5
from certificate import PQ_DigitalCertificate

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

BOB_DIGITAL_CERTIFICATE = None
ALICE_DIGITAL_CERTIFICATE = None

PQ_FLAG = True

def send_large_data(data, sock,address, chunk_size=4096):
    # Split data into chunks
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        sock.sendto(chunk, address)
    # Send an empty chunk to indicate the end of the transmission
    sock.sendto(b'', address)

class MyUDPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        global BOB_DIGITAL_CERTIFICATE
        global ALICE_DIGITAL_CERTIFICATE
        global BOB_CIPHER_RSA
        global BOB_PUBLIC_KEY
   
        encrypted_data = self.request[0].strip()
        socket = self.request[1]
        if b"get_certificate_from_alice " in encrypted_data:
            len_data = len("get_certificate_from_alice ")
            data = encrypted_data[len_data:]
            BOB_DIGITAL_CERTIFICATE = pickle.loads(data)
            if not check_valid_certificate(BOB_DIGITAL_CERTIFICATE):
                print("Invalid certificate")
                exit(0)
            BOB_PUBLIC_KEY = BOB_DIGITAL_CERTIFICATE.certificate_body.subject_public_key
            BOB_CIPHER_RSA = PKCS1_OAEP.new(RSA.import_key(BOB_PUBLIC_KEY))
            
            temp_a_cert = pickle.dumps(ALICE_DIGITAL_CERTIFICATE)
            send_large_data(temp_a_cert, socket, self.client_address)
            # socket.sendto(temp_a_cert, self.client_address)
        else:
            data = ALICE_DECIPHER_RSA.decrypt(encrypted_data)
            # data = encrypted_data
            print("{} wrote: {}".format(self.client_address[0], data))
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
    if PQ_FLAG: 
        body = ds.certificate_body
        data = pickle.dumps(body)
        val_bytes = bytearray(data)
        temp = ''.join(['%02x' % byte for byte in val_bytes])
        res = Dilithium5.verify(SERVER_DILITHIUM_PUBLIC_KEY,str.encode(temp), ds.certificate_signature)
        return res
    else:
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
    
    with socketserver.UDPServer((HOST, ALICE_PORT), MyUDPHandler) as server:
        server.serve_forever()


def create_certificate():
    name = input("Enter name: ").encode()
    PRIVATE_KEY = RSA.generate(1024)
    PUBLIC_KEY = PRIVATE_KEY.publickey()
    message = b"create_certificate_user <" + name + b"> " + PUBLIC_KEY.export_key("OpenSSH")
    data = SERVER_CIPHER_RSA.encrypt(message)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(data)
        received = recvall(sock)
        print(received)

def revoke_certificate():
    name = input("Enter name: ").encode()
    message = b"revoke_certificate_user <" + name + b">"
    data = SERVER_CIPHER_RSA.encrypt(message)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(data)
        received = recvall(sock)
        print(received)


def fetch_certificate():
    name = input("Enter name: ").encode()
    message = b"fetch_certificate_user <" + name + b">"
    data = SERVER_CIPHER_RSA.encrypt(message)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(data)
        received = recvall(sock)
        msg_received = pickle.loads(received)
        if type(msg_received) == PQ_DigitalCertificate:
            print("Certificate fetched successfully")
            USER_CERTIFICATE = msg_received
            return
        if b"error 101" in msg_received:
            print("Error: Certificate revoked")
        elif b"error 102" in msg_received:
            print("Error: User doesn't exist")

def cli_loop():
    while(True):
        print("1- Create certificate")
        print("2- Revoke certificate")
        print("3- Fetch certificate")
        print("4- Exit")
        user_input = int(input("Enter Option: "))
        if user_input == 1:
            create_certificate()
        if user_input == 2:
            revoke_certificate()
        if user_input == 3:
            fetch_certificate()
        elif user_input == 4:
            print("User exited")
            exit(0)
        else:
            print("Enter Valid Input")

def cli():
    print("User logged in")
    cli_loop()

if __name__ == "__main__":
    cli()