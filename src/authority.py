import socketserver
from common import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from certificate import *
import pickle
import secrets
import string
from user import get_public_key_from_dict
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import gzip

def generate_alphanumeric_uuid(length=12):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

uuid_string = generate_alphanumeric_uuid()
ds_dict = {}

PQ_FLAG = False

def send_large_data(data, sock,address, chunk_size=4096):
    # Split data into chunks
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        sock.sendto(chunk, address)
    # Send an empty chunk to indicate the end of the transmission
    sock.sendto(b'', address)

def generatePath():
    uuid = generate_alphanumeric_uuid()
    return f"./certificates/users/{uuid}.pem.gz"

def writeDigitalCertificate(pq_dcert, path):
    with gzip.open(path, "wb+") as f:
        pickle.dump(pq_dcert, f)
        
        

def insertEntryToSQL(name, path):
    session = get_sql_session()
    sql_string = f"INSERT INTO certificates VALUES( \"{name}\", \"{path}\") ; "
    session.execute(text(sql_string))
    session.commit()
    
def getEntryFromCAList(name):
    session = get_sql_session()
    sql_string = f"SELECT * FROM certificates where name = \"{name}\" LIMIT 1"
    rows = session.execute(text(sql_string))
    res = rows.fetchall()
    if(len(res) == 0 ):
        return None
    if(len(res) > 1):
        return None
    return res[0]

def addCRL(row):
    session = get_sql_session()
    sql_string = f"INSERT INTO crl_list VALUES(\"{row[0]}\", \"{row[1]}\");"
    session.execute(text(sql_string))
    session.commit()
    
def getCRLCount(name):
    session = get_sql_session()
    sql_string = f"SELECT * FROM crl_list WHERE name = \"{name}\""
    rows = session.execute(text(sql_string))
    res = rows.fetchall()
    if len(res) > 0:
        sql_string_delete = f"DELETE FROM crl_list WHERE name = \"{name}\""
        rows = session.execute(text(sql_string_delete))
        sql_string_delete = f"DELETE FROM certificates WHERE name = \"{name}\""
        rows = session.execute(text(sql_string_delete))
        session.commit()
        return True
    else:
        return False

def getCertificate(name):
    session = get_sql_session()
    sql_string = f"SELECT * FROM certificates where name = \"{name}\" LIMIT 1"
    rows = session.execute(text(sql_string))
    res = rows.fetchall()
    if len(res) == 0:
        return False
    else:
        res = res[0]
        path = res[1]
        with gzip.open(f"{path}", "rb") as f:
            data_res = pickle.load(f)
            return data_res

class MyUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        encrypted_data = self.request[0].strip()
        data = SERVER_DECIPHER_RSA.decrypt(encrypted_data)
        socket = self.request[1]
        print("{} wrote:".format(self.client_address[0]))
        print(data)
        
        if b"create_certificate_bob" in data:
            if not PQ_FLAG:
                USER_PUBLIC_KEY =  RSA.import_key(data[23:])
                certificate_bob = Certificate("BOB",USER_PUBLIC_KEY.export_key())
                ds = DigitalCertificate(certificate_bob)
                ds_dict["BOB"] = ds
                socket.sendto(pickle.dumps(ds), self.client_address)
            else:
                USER_PUBLIC_KEY =  RSA.import_key(data[23:])
                certificate_bob = Certificate("BOB",USER_PUBLIC_KEY.export_key())
                ds = PQ_DigitalCertificate(certificate_bob)
                ds_dict["BOB"] = ds
                send_large_data(pickle.dumps(ds), socket,self.client_address)
        elif b"create_certificate_alice" in data:
            if not PQ_FLAG:
                USER_PUBLIC_KEY =  RSA.import_key(data[25:])
                certificate_alice = Certificate("ALICE",USER_PUBLIC_KEY.export_key())
                ds = DigitalCertificate(certificate_alice)
                ds_dict["ALICE"] = ds
                socket.sendto(pickle.dumps(ds), self.client_address)
            else:
                USER_PUBLIC_KEY =  RSA.import_key(data[25:])
                certificate_alice = Certificate("ALICE",USER_PUBLIC_KEY.export_key())
                ds = PQ_DigitalCertificate(certificate_alice)
                ds_dict["ALICE"] = ds
                send_large_data(pickle.dumps(ds), socket, self.client_address)

        elif b"get_certificate_alice" in data:
            socket.sendto(pickle.dumps(ds_dict["ALICE"]),self.client_address)
        elif b"get_certificate_bob" in data:
            socket.sendto(pickle.dumps(ds_dict["BOB"]),self.client_address)
        elif b"create_certificate_user" in data:
            lindex = data.find(b'<')
            rindex = data.find(b'>')
            name = data[lindex+1 : rindex].decode("utf-8")
            path = generatePath()
            USER_PUBLIC_KEY = RSA.import_key(data[rindex + 2:])
            certificate_user = Certificate(name,USER_PUBLIC_KEY.export_key())
            ds = PQ_DigitalCertificate(certificate_user)
            writeDigitalCertificate(ds, path)
            insertEntryToSQL(name, path )
            cert_id = str(certificate_user.serial_no)
            with open("./certificates/CAL_CRL_certs/CAlist.txt", "a") as file:
                file.write(cert_id + "\n")
            socket.sendto(b"Created certificate successfully", self.client_address)

        elif b"revoke_certificate_user" in data:
            lindex = data.find(b'<')
            rindex = data.find(b'>')
            name = data[lindex+1 : rindex].decode("utf-8")
            signature_name = data[rindex + 1:]
            row = getEntryFromCAList(name)
            if row == None:
                send_large_data(pickle.dumps(b"error 102"), socket, self.client_address)
                return
            cert : PQ_DigitalCertificate = getCertificate(row[0])
            # DECIPHER_RSA = PKCS1_OAEP.new(get_public_key_from_dict(name.encode()))
            verify_res = pkcs1_15.new(RSA.import_key(cert.certificate_body.subject_public_key))
            try:
                verify_res.verify(SHA256.new(name.encode()),signature_name)
            except:
                socket.sendto(b"Invalid message", self.client_address)
                return
            addCRL(row)
            socket.sendto(b"Certificate revoked sucessfully", self.client_address)
            return
             
        elif b"fetch_certificate_user" in data:
            lindex = data.find(b'<')
            rindex = data.find(b'>')
            name = data[lindex+1 : rindex].decode("utf-8")
            try:
               if getCRLCount(name):
                    send_large_data(pickle.dumps(b"error 102"), socket, self.client_address)
                    return
               res = getCertificate(name)
               if res == False:
                    send_large_data(pickle.dumps(b"error 101"), socket, self.client_address)
                    return
                    
               send_large_data(pickle.dumps(res), socket, self.client_address)
               
            except:
                print("Internal server error")
                send_large_data(pickle.dumps(b"error 102"), socket, self.client_address)
        

def run_server(port):
    HOST = "localhost"
    print(f"Certificate Server running on host: {HOST} and port: {port} ")
    with socketserver.UDPServer((HOST, port), MyUDPHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    HOST, PORT = "localhost", 9998
    print(f"Certificate Server running on host: {HOST} and port: {PORT} ")
    with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
        server.serve_forever()