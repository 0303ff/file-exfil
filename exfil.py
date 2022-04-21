from socket import *
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
    buf = 1024
    addr = (host, int(port))
    UDPSock = socket(AF_INET, SOCK_DGRAM)
    UDPSock.bind(addr)
    print("Waiting to receive file...")
    while True:
        (data, addr) = UDPSock.recvfrom(buf)
        msg = f.decrypt(data)
        with open(file, 'wb') as decrypted_file:
            decrypted_file.write(msg)
        break
    UDPSock.close()

def Client(ip, port, file):
    keygen()
    addr = (ip, int(port))
    UDPSock = socket(AF_INET, SOCK_DGRAM)
    while True:
        with open(file, 'rb') as fs:
            file = fs.read()
        ciphertext = f.encrypt(file)
        UDPSock.sendto(ciphertext, addr)
        break
    UDPSock.close()

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
