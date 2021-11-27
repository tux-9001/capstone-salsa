#TODO: begin work on server CLI
run=True
configfile = open("serverconfig", "r")
import socket
import os
class cfgVal():
    def __init__(self,type,value):
        self.type = type
        self.value = value
def FileParser9000():
    returnlist=[]
    #This parses the config file for data and returns a list of configuration data
    parse=True
    #TODO: make this translate textfiles into lists
    while parse:
        for line in configfile:
            v = line.split()
            print(v[0], v[1])
            returnlist.append(cfgVal(v[0], v[1]))
            if line == "":
                parse=False
        for obj in returnlist:
            print(obj.type)
            print(obj.value)
        return returnlist


host=''
port=''
cfgl=FileParser9000()
print (cfgl)

#configuration=FileParser9000(configfile)
for object in cfgl:
    print ("ITEM",object.type)
    print ("DATA",object.value)
    if object.type=='HOST':
        host=(str(object.value))
        #why wont it interpret this correctly
    if object.type=='PORT':
        port=(int(object.value))

#s.bind(('',port))
r = False
while run:
    #Main mehu/app loop
    menuOpt=input("Welcome to salsa's server interface, type 's' to start server, 'v' or 'view' to view collected data, or 'x'/'exit' to exit.\n")
    if menuOpt =="s" or menuOpt =="start":
        print("Attempting to start socket with host: {0} and port: {1}".format(host,port))
        print("You can change the host & port in serverconfig.")
        while True:
            s = socket.socket()
            # The code below binds to socket
            s.bind(('', port))
            # Amount of connections that can be open at the same time
            s.listen(5)
            c, addr = s.accept()
            print ("got connection from", addr)
            #Accepts connections
            while True:
                #This loop receives data sent from the other side
                c.send('Connected ok'.encode())
                received=c.recv(1024)
                print (received.decode())
                receivedstr=(received.decode('utf-8'))
                print("b")
                strS="s"
                print (len(received))
                if receivedstr == strS:
                    print ("its s")
                if len(received) == 2: #Closes the socket- set this to 0 in normal use. If over telnet use 2 (length of \n)
                    break





        #TODO: COMPLETE CONFIGURING SOCKET
    if menuOpt=="x" or menuOpt == "exit":
        run = False

