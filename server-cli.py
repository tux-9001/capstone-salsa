run = True
configfile = open("serverconfig", "r")
import socket , subprocess
l1 = []
viewlist = []
listname = ''
score1 = ''
dss1 = ''

class cfgVal():
    def __init__(self, type, value):
        self.type = type
        self.value = value


class lobj:
    def __init__(self, hostname, desc, score, dss, id):
        self.hostname = hostname
        self.desc = desc
        self.score = score
        self.dss = dss
        self.id = id

def DuplicateDestroyer9000(hn,ide):
    #This function is used to remove duplicate items from a list.
    for lobj in l1:
        if lobj.hostname == hn and lobj.id == ide:
            print("duplicate!!!!!!!",lobj.id,lobj.hostname)
            print(hn,ide)
            l1.pop()


def FileParser9000():
    returnlist = []
    # This parses the config file for data and returns a list of configuration data
    parse = True

    while parse:
        for line in configfile:
            v = line.split()

            returnlist.append(cfgVal(v[0], v[1]))
            if line == "":
                parse = False

        return returnlist





cfgl = FileParser9000()

#The below block of code sets up the control vars.
for object in cfgl:

    if object.type == 'HOST':
        host = (str(object.value))
        print(host)
    if object.type == 'PORT':
        port = (int(object.value))
    if object.type == 'DEBUG':
        debug = int(object.value)
    if object.type == 'LOGNAME':
        #This increments the logfile name by 1 so they are not overwritten.
        logname = object.value
        cmd = subprocess.run(['ls | grep ' + logname + '| tail -1'], shell=True, capture_output=True)
        print(cmd)
        cstr = cmd.stdout.decode('utf-8')
        print(cstr)
        # checks for presence of the logfile and what its incremented by
        if logname in cstr:
            svr = 0


            if logname in cstr:
                print('aaaaa')
                try:
                    if int(cstr.strip(logname+'\n'+'0')) >= 0:
                        print("WARN!!!!")
                        svr=1
                        svr += int(cstr.strip(logname+'\n'+'0'))
                        print(svr)
                except ValueError:
                    if logname+'0' in cstr:
                        print('zero')
                        svr=1
                    pass

            filename = (logname + str(svr))
        else:
            filename = logname


    # Setting 'debug' to 1 will print all network related log messages to the console.
class MachineList:
    def __init__(self,hostname,li1,score,dss):
        self.hostname=hostname
        self.list=[]
        self.li1=li1
        self.score=score
        self.dss=dss
        #This makes displaying data easier by providing a way to put all info for a specific host
        #Under a singular object
        #Use nested forloops to interate through list
        self.list.extend(li1)



def finalize(array, logfilenm):
    # compiles a report by writing ll (list of security items) to the logfile
    # also creates said logfile
    filename = logfilenm




    log = open(filename, 'w')
    print("Log made, filename:", filename)
    fsc = 0
    dscTotal = 0
    dssSc = 0
    # Code below writes log items into log. Ensure you strip newline chars if applicable.
    for object in array:
        print(object.hostname)
        for lobj in object.list:
            print(lobj.hostname)
            print(lobj.score)
            fsc += int(lobj.score)
            dscTotal += int(lobj.dss)
            log.write('"' + hostname + '"')
            log.write("")
            log.write('"' + lobj.desc + '"')
            log.write(" ")
            log.write(str(lobj.score))
            log.write(" ")
            log.write(str(lobj.dss))
            log.write(" ")
            log.write(str(lobj.id))
            log.write("\n")
            if int(lobj.score) > 0 and int(lobj.dss) == 1:
                dssSc += int(lobj.score)
    print("Total score is", fsc)
    print("PCI-DSS score is:", dssSc)
    log.write("Security item format: hostname, description, check ID, DSS score, and score.")



r = True
while run:
        print("Attempting to start socket with host: {0} and port: {1}".format(host, port))
        print("You can change the host & port in serverconfig.")
        while r:
            s = socket.socket()
            # The code below sets socket options. Specifically, it sets the type to TCP and allows it to reuse an address
            # Instead of waiting
            s.setsockopt(socket.SOCK_STREAM, socket.SO_REUSEADDR, 1)
            s.bind((host,port))

            # Amount of connections that can be open at the same time
            s.listen(5)
            c, addr = s.accept()
            print("got connection from", addr)
            currentaddr=addr
            # Accepts connections
            ctr = True

            while ctr:
                try:
                    # This loop receives and sends data to the client.
                    c.send(' '.encode())
                    print(currentaddr)
                    received = c.recv(1024)
                    receivedstr = (received.decode('utf-8'))
                    rstrb = receivedstr.strip()
                    if debug == 1:
                        # Displays received data in debug mode. Not necessary in normal operation
                        print("Received data:", received.decode())
                        print("Stripped received data:", rstrb)
                        print("Length of received data:", len(received))
                    if '<VIEW>ALL' in rstrb and '127.0.0.1' in currentaddr:
                        for obj in viewlist:
                            c.send(('Items for host '+obj.hostname+'\n').encode())
                            for lobj in obj.list:
                                c.send(("Desc: " + lobj.desc + " " + "Score: " + str(lobj.score) + " " + "DSS: " + str(
                                    lobj.dss) + " " + " ID: " + str(lobj.id)).encode())
                                c.send('\n'.encode())
                        c.send('<E>'.encode())

                    if '<VIEW>' in rstrb and '127.0.0.1' in currentaddr and rstrb != '<VIEW>ALL':

                        c.send(('Host set to: '+str(host)).encode())
                        c.send('\n'.encode())
                        c.send(('Port set to: '+str(port)).encode())
                        c.send('\n'.encode())
                        c.send(('Debug set to: '+str(debug)).encode())
                        c.send('\n'.encode())
                        c.send(('Current log filename: '+str(filename)).encode())
                        c.send('\n'.encode())
                        for obj in viewlist:
                            print(obj.hostname)
                            print(obj.score)

                        try:
                            rstrb=rstrb.removeprefix('<VIEW>')
                            print(rstrb)
                            #syntax: <VIEW>hostname
                            for object in viewlist:
                                print (object.list)


                                if object.hostname in rstrb:
                                    c.send(('Displaying security items for hostname: '+object.hostname+'\n').encode())
                                    print(object.list)
                                    for lobj in object.list:

                                        c.send(("Desc: "+lobj.desc+" "+"Score: "+str(lobj.score)+" "+"DSS: "+str(lobj.dss)+" "+" ID: "+str(lobj.id)).encode())
                                        c.send('\n'.encode())
                            c.send('<E>'.encode())



                        except NameError:
                            pass


                    if rstrb == "<EXIT>":
                        print("RECEIVED EXIT COMMAND. STOPPING")
                        # Closes socket. setting ctr to False breaks out of the send/receive loop
                        # So the program doesn't attempt to send data via a nonexistent socket
                        c.close()
                        try:
                            for object in viewlist:
                                if object.hostname == hostname:
                                    print("Duplicate list destroyed")
                                    viewlist.pop()
                            viewlist.append(MachineList(hostname,l1,score,dss))
                        except NameError:
                            print("Received EXIT, but didn't receive any data.")
                        print(viewlist)



                        finalize(viewlist, filename)
                        l1.clear()
                        for object in viewlist:
                            print(object.list)
                            for obj in object.list:
                                print(obj.hostname,obj.id,obj.score)
                                hostname=''
                        ctr = False
                        break

                    ctrv = 0
                    # Code below determines where data is supposed to go by tag
                    # Then removes the prefix and stores it in a lobj
                    # Note that the lobj class here is different, I added a hostname variable to determine
                    # The origin system so you can see what needs changing on each host

                    if '<HOST>' in rstrb:
                        print("Received HOSTNAME")
                        e = rstrb.removeprefix('<HOST>')
                        print(e)
                        hostname = e
                        print(hostname)
                    if '<DESC>' in rstrb:
                        print("Received DESC")
                        e = rstrb.removeprefix('<DESC>')
                        print(e)
                        desc = e
                    if '<ID>' in rstrb:
                        print("Received ID")
                        e = rstrb.removeprefix('<ID>')
                        print(e)
                        ide = e
                    if '<SCORE>' in rstrb:
                        print("Received SCORE")
                        e = rstrb.removeprefix('<SCORE>')
                        print(e)
                        score = e
                    if '<DSS>' in rstrb:
                        print("Received DSS")
                        e = rstrb.removeprefix('<DSS>')
                        print(e)
                        dss = e
                    if '<END>' in rstrb:
                        try:
                            DuplicateDestroyer9000(hostname,ide)

                            print("Received end command")
                            print(hostname, desc, score, dss, ide)
                            l1.append(lobj(hostname, desc, score, dss, ide))

                            print(l1)
                        except NameError:
                            c.send('<ERR:PARAM>'.encode())
                            print("Error: client didn't send all parameters before ending")
                    if '<QUIT>' in rstrb and '127.0.0.1' in currentaddr:
                        c.close()
                        ctr=False
                        run=False
                        r=False
                        break




                except ConnectionResetError:
                    print("Connection reset by peer!!!")
                    pass
                    ctr = False
                # Handles CREs.

