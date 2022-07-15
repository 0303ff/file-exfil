import socket
import base64, getpass, argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def keygen():
    global f
    password = bytes(getpass.getpass("Password: "), "utf-8")
    salt = bytes(getpass.getpass("Salt: "), "utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)


def Serv(port, file):
    keygen()
    host = ""
    buf = 1000000000 # < 1 gig / change this based on the size of your file. 
    addr = (host, int(port))
    Sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    Sock.bind(addr)
    print("Waiting to receive file...")
    Sock.listen(5)
    conn, C_addr = Sock.accept()
    print(f"Connection from: {C_addr}")
    while True:
        data=conn.recv(buf, socket.MSG_WAITALL)
        if data == b"":
            break
        msg = f.decrypt(data)
    with open(file, 'wb') as decrypted_file:
        decrypted_file.write(msg)
    print("File transfer complete")
    Sock.close()

def Client(ip, port, file):
    keygen()
    addr = (ip, int(port))
    Sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    Sock.connect(addr)
    while True:
        with open(file, 'rb') as fs:
            file = fs.read()
        ciphertext = f.encrypt(file)
        Sock.sendall(ciphertext)
        break

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-s","--server", help="Recv File", action='store_true')
    parser.add_argument("-c","--client", help="Send File", action='store_true')
    parser.add_argument("-i","--ip", help="Server IP")
    parser.add_argument("-p","--port", help="Server Port")
    parser.add_argument("-f","--file", help="File")
    args = parser.parse_args()

    if args.server:
        if args.port:
            if args.file:
                Serv(args.port, args.file)
            else:
                print("name of file required")
        else:
            print("port required")
    if args.client:
        if args.ip:
            if args.port:
                if args.file:
                    Client(args.ip, args.port, args.file)
                else:
                    print("file required")
            else:
                print("port required")
        else:
            print("ip required")

main()
