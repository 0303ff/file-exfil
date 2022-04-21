# file-exfil

Using the cryptography module to send files over a network encrypted.  

### Install cryptography  
`python3 -m pip install cryptography` 

### Running  

Receive a file:    
`python3 exfil.py -s -p <port> -f nameFile2save.txt`  
Send a file:  
`python3 exfil.py -c -i <server_ip> -p <port> -f file2send.txt`  
