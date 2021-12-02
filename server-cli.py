
run=True
configfile = open("serverconfig", "r")
import socket
import subprocess
l1=[]

class cfgVal():
    def __init__(self,type,value):
        self.type = type
        self.value = value
class lobj():
    def __init__(self,hostname,desc,score,dss,id):
        self.hostname = hostname
        self.desc=desc
        self.score = score
        self.dss = dss
        self.id = id
def FileParser9000():
    returnlist=[]
    #This parses the config file for data and returns a list of configuration data
    parse=True
    #TODO: make this translate textfiles into lists
    while parse:
        for line in configfile:
            v = line.split()

            returnlist.append(cfgVal(v[0], v[1]))
            if line == "":
                parse=False

        return returnlist
def finalize(array):
    # compiles a report by writing ll (list of security items) to the logfile
    #also creates said logfile
    filename = ""
    ovwr = ""
    checkls = subprocess.run(['ls'], capture_output=True, shell=True)
    checklsstr = checkls.stdout.decode("utf-8")
    frun = True
    while frun:
        #Checks filename presence and makes the actual file
        filename = input("Please enter a name for the logfile\n")
        if filename in checklsstr:
            ovwr = input("Warn: a file appears to exist under this name. Overwrite?\n")
        if ovwr == "y":
            log = open(filename, 'w')
            frun = False
        if filename not in checklsstr:
            log = open(filename, 'w')
            frun = False
    fsc = 0
    dscTotal = 0
    dssSc= 0
    # Code below writes log items into log. Ensure you strip newline chars if applicable.
    for lobj in array:
        fsc += lobj.score
        dscTotal += lobj.dss
        log.write('"'+hostname+'"')
        log.write("")
        log.write('"'+lobj.desc+'"')
        log.write(" ")
        log.write(str(lobj.score))
        log.write(" ")
        log.write(str(lobj.dss))
        log.write(" ")
        log.write(str(lobj.id))
        log.write("\n")
        if lobj.score > 0 and lobj.dss == 1:
            dssSc += lobj.score
    print("Total score is", fsc)
    print("PCI-DSS score is:", dssSc)
    log.write("Security item format: description, check ID, DSS score, and score.")


host=''
port=''
debug=''
cfgl=FileParser9000()


#configuration=FileParser9000(configfile)
for object in cfgl:

    if object.type=='HOST':
        host=(str(object.value))
        #why wont it interpret this correctly
    if object.type=='PORT':
        port=(int(object.value))
    if object.type=='DEBUG':
        debug=int(object.value)
    #Setting 'debug' to 1 will print all network related log messages to the console.

#s.bind(('',port))
r = False
while run:
    #Main mehu/app loop
    menuOpt=input("Welcome to salsa's server interface, type 's' to start server, 'v' or 'view' to view collected data, or 'x'/'exit' to exit.\n")
    if menuOpt =="s" or menuOpt =="start":
        print("Attempting to start socket with host: {0} and port: {1}".format(host,port))
        print("You can change the host & port in serverconfig.")
        #TODO:Convert server loop into a fn to provide read access while running network
        while True:
            s = socket.socket()
            # The code below sets socket options. Specifically, it sets the type to TCP and allows it to reuse an address
            #Instead of waiting
            s.setsockopt(socket.SOCK_STREAM, socket.SO_REUSEADDR, 1)
            s.bind(('', port))

            # Amount of connections that can be open at the same time
            s.listen(5)
            c, addr = s.accept()
            print ("got connection from", addr)
            #Accepts connections
            ctr=True

            while ctr:
                try:
                #This loop receives and sends data to the client.
                    c.send('<START>'.encode())
                    received=c.recv(1024)
                    receivedstr=(received.decode('utf-8'))
                    rstrb=receivedstr.strip()
                    if debug == 1:
                        #Displays received data in debug mode. Not necessary in normal operation
                        print("Received data:",received.decode())
                        print("Stripped received data:",rstrb)
                        print ("Length of received data:",len(received))
                    if rstrb == "<EXIT>":
                        #Closes socket. setting ctr to False breaks out of the send/receive loop
                        #So the program doesn't attempt to send data via a nonexistent socket
                        c.close()
                        ctr = False
                        break

                    ctrv=0
                # Code below determines where data is supposed to go by tag
                # Then removes the prefix and stores it in a lobj
                #Note that the lobj class here is different, I added a hostname variable to determine
                #The origin system so you can see what needs changing on each host


                    if '<HOST>' in rstrb:
                        print("Received HOSTNAME")
                        e=rstrb.removeprefix('<HOST>')
                        print (e)
                        hostname = e
                        print(hostname)
                    if '<DESC>' in rstrb:
                        print ("Received DESC")
                        e=rstrb.removeprefix('<DESC>')
                        print (e)
                        desc = e
                    if '<ID>' in rstrb:
                        print("Received ID")
                        e=rstrb.removeprefix('<ID>')
                        print(e)
                        ide = e
                    if '<SCORE>' in rstrb:
                        print("Received SCORE")
                        e=rstrb.removeprefix('<SCORE>')
                        print(e)
                        score = e
                    if '<DSS>' in rstrb:
                        print("Received DSS")
                        e=rstrb.removeprefix('<DSS>')
                        print(e)
                        dss = e
                    if '<END>' in rstrb:
                        try:
                            print("Received end command")
                            print(hostname,desc,score,dss,ide)
                            l1.append(lobj(hostname,desc,score,dss,ide))
                            print(l1)
                        except NameError:
                            c.send('<ERR:PARAM>'.encode())
                            print("Error: client didn't send all parameters before ending")




                except ConnectionResetError:
                    print("Connection reset by peer!!!")
                    pass
                    ctr = False
                #Handles CREs.



    if menuOpt=="x" or menuOpt == "exit":
        run = False

