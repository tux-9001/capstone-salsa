import socket
import time
#This is a simple test program I was using to send data to the server and view its reaction
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('127.0.0.1',9848))
print (s.recv(1024).decode())
s.send("hi".encode())
time.sleep(1)
s.send("b!EXIT!b".encode())
s.close()
