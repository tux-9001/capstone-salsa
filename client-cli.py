import time

run = True
configfile = open("clientconfig", "r")
import subprocess
import socket
def GetNumber(string):
    #This returns a single int from a string
    for word in string.split():
        if word.isdigit():
            return word

class lobj:
    def __init__(self, desc, score, dss, id):
        self.desc = desc
        self.score = score
        self.dss = dss
        self.id = id
        # Append to log[] list- this should determine final score
        # Will add these up at the end of security chk
        # Use desc value to describe why this score applies
        # The "dss" variable exists to make PCI-DSS compliance auditing easier
        # sysadmins should be able to use this to audit dss compliance


# PLEASE RUN THIS FROM TERMINAL, NOT PYCHARM!
# PYCHARM DOES *NOT* PROVIDE SUDO ACCESS!
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
    for lobj in array:
            fsc += int(lobj.score)
            dscTotal += int(lobj.dss)
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

    log = open(filename, 'w')
    fsc = 0
    dscTotal = 0
    dssSc= 0
    # Code below writes log items into log. Ensure you strip newline chars if applicable.
    for lobj in array:
        fsc += lobj.score
        dscTotal += lobj.dss
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

    log = open(filename, 'w')
def FileParser9000():
    class cfgVal():
        def __init__(self, type, value):
            self.type = type
            self.value = value
    returnlist=[]
    #This parses the config file for data and returns a list of configuration data
    parse=True

    while parse:
        for line in configfile:
            v = line.split()

            returnlist.append(cfgVal(v[0], v[1]))
            if line == "":
                parse=False

        return returnlist

ll = []
confl=FileParser9000()
for object in confl:

    if object.type == 'HOST':
        host = (str(object.value))
    if object.type == 'PORT':
        port = (int(object.value))
    if object.type == 'DEBUG':
        debug = int(object.value)
    if object.type == 'LOGNAME':
        #This increments the logfile name by 1 so they are not overwritten.
        logname = object.value
        cmd = subprocess.run(['ls | grep ' + logname + '| tail -1'], shell=True, capture_output=True)

        cstr = cmd.stdout.decode('utf-8')
        print(cstr)
        # checks for presence of the logfile and what its incremented by
        if logname in cstr:

            svr = 0
            try:
                if int(cstr.strip(str(logname)+'\n'+'0')) >= 0:
                    print("WARN!!!!")
                    svr = 1
                    svr += int(cstr.strip(str(logname)+'\n'+'0'))
            except ValueError:
                if logname + '0' in cstr:
                    print('zero')
                    svr = 1
            filename = (logname + str(svr))
        else:
            filename = logname
        print(logname)


def CheckSecurity():
    finalscore = 0
#to  do resolved. checks work for diff distros without issue.
    checkDistroName = subprocess.run(['cat /etc/*-release | grep PRETTY_NAME | head -1'],capture_output=True, shell=True)
    #could simplify command
    checkDistroNameStr = checkDistroName.stdout.decode('utf-8')
    checkDistroNameStrL = checkDistroNameStr.strip()
    ll.append(lobj(checkDistroNameStrL,0,0,0))
    #Check name of distro
    isrootlogin = subprocess.run(['sudo grep "PermitRootLogin" /etc/ssh/sshd_config | head -n 1'], capture_output=True,
                                 shell=True)
    isrootloginstr = isrootlogin.stdout.decode("utf-8")
    print(isrootloginstr)
    # Checks for root login over ssh w/ password- disable this
    if "prohibit-password" in isrootloginstr:
        ll.append(lobj("No root login with password over SSH", 10, 0, 1))
        print("Root login with password is disabled via SSH.")
    if "no" in isrootloginstr:
        ll.append(lobj("No root login with password over SSH", 10, 0, 1))
        print("Root login with password is disabled via SSH.")
    if "yes" in isrootloginstr:
        ll.append(lobj("Warning- root login enabled via SSH.", -10, 0, 1))
        print("Warning- root login enabled via SSH."
              " \nTo prevent bruteforce attacks,\n"
              " change the 'permitrootlogin' setting in your SSH config to 'no' or 'prohibit-password'")
    else:
        print("OpenSSH doesn't appear to be installed")
        ll.append((lobj("No SSH server",10,0,1)))
    selinuxenf = subprocess.run(['getenforce | head -n 1'], capture_output=True, shell=True)
    selinuxenfstr = selinuxenf.stdout.decode("utf-8")
    strEnforcing = ("Enforcing")
    strPermissive = ("Permissive")

    if strEnforcing in selinuxenfstr:
        print("SELinux is set to enforcing. This makes it more difficult for malicious actors to modify files.")
        ll.append(lobj("Success- SELinux enforcing", 10, 0, 2))
    if strPermissive in selinuxenfstr:
        print("SELinux is set to permissive- this doesn't prevent violations!")
        print("To set SELinux to enforcing, run 'sudo setenforce 1'.")
        ll.append(lobj("Warning- SELinux is set to permissive!", -10, 0, 2))
        # Checks SELinux status
    else:

        #Will check AppArmor if SELinux doesn't appear to be present
        #First check tries to see if apparmor is running at all
        appArmorCheck = subprocess.run(['sudo aa-status | grep "apparmor module"'],capture_output=True, shell=True)
        appArmorCheckStr = appArmorCheck.stdout.decode('utf-8')
        isAAonStr=("is loaded")
        isAAoffStr=("not loaded")
        if isAAonStr in appArmorCheckStr:
            print("Apparmor loaded")
            ll.append((lobj("Apparmor loaded",5,0,2)))
        if isAAoffStr in appArmorCheckStr:
            print ("Warning! Apparmor disabled")
            ll.append(lobj("Apparmor off!",0,0,2))
        #Second check is comparing the number of enforcing profiles to loaded, most should be enforcing
        appArmorLP = subprocess.run(['sudo aa-status | grep "profiles are loaded"'],shell=True, capture_output=True)
        print(appArmorLP)
        appArmorLPStr = appArmorLP.stdout.decode('utf-8')

        appArmorEP = subprocess.run(['sudo aa-status | grep "profiles are in enforce"'],shell=True, capture_output=True)
        print(appArmorEP)
        appArmorEPstr = appArmorEP.stdout.decode('utf-8')
        appArmorEPno=0
        appArmorLPno=0
        AA=True
        try:
            appArmorEPno = int(GetNumber(appArmorEPstr))
            appArmorLPno = int(GetNumber(appArmorLPStr))
        except TypeError:
            print ("no apparmor")
            AA=False
            #This disables the apparmor checks if it isn't installed. That way, results are accurate

        if appArmorEPno != appArmorLPno and AA:
            print("Warning: not all apparmor profiles are enforcing!")
            print((appArmorLPno - appArmorEPno),"profiles not enforcing")
            ll.append(lobj("Not all AA profiles enforcing.",0,0,3))
        if appArmorEPno == appArmorLPno and AA:
            print("All apparmor profiles are enforcing.")
            ll.append(lobj("All AA profiles enforcing.",5,0,3))



    isInsecureFTP = subprocess.run(['sudo netstat -nlp | grep ftp'], capture_output=True, shell=True)
    isInsecureFTPstr = isInsecureFTP.stdout.decode("utf-8")
    vsftpd = ("vsftpd")
    if vsftpd in isInsecureFTPstr:
        # Checks vsftpd's configuration for
        vsftpdchk = subprocess.run(['sudo cat /etc/vsftpd/vsftpd.conf | grep ssl_tlsv1'], capture_output=True,
                                   shell=True)
        vssec = vsftpdchk.stdout.decode("utf-8")
        sslcheckstr = ("ssl_tlsv1=YES")
        nofilestr = ("No")
        print(vssec)
        # TO DO: automatically check other ftp services for security
        #att not a to do as vsftpd seems to be super common
        if sslcheckstr not in vssec:
            print("Warning: FTP service is running in cleartext mode")
            ll.append(lobj("FTP on and insecure", 0, 1, 4))
        if sslcheckstr in vssec:
            print("VSFTPD is enabled and secured.")
            ll.append(lobj("VSFTPD secured.", 0, 1, 4))
    else:
        print("FTP appears to be disabled.")
        ll.append(lobj("FTP off", 0, 1, 4))
        # Checks FTP security
    checkfirewall = subprocess.run(['lsmod | grep table'], capture_output=True, shell=True)
    checkfirewallstr = checkfirewall.stdout.decode("utf-8")
    nftablesstr = ("nf_tables")
    iptablesstr = ("ip_tables")
    print(checkfirewallstr)
    if nftablesstr in checkfirewallstr:
        # Checks if firewall is enabled
        print("iptables enabled. Please ensure that it's configured correctly")
        ll.append(lobj("nftables firewall enabled. Check cfg", 10, 1, 5))
    else:
        if iptablesstr in checkfirewallstr:
            print("iptables enabled. Please ensure that it's configured correctly")
            ll.append(lobj("iptables firewall enabled. Check cfg", 10, 1, 5))
        else:
            print("Warning: no firewall detected! This is a major security risk")
            ll.append(lobj("Warning: no firewall", 0, 1, 5))
    print(checkDistroNameStrL)
    strFedora=("Fedora")
    strCentOS=("CentOS")
    strUbuntu=("Ubuntu")
    strRHEL=("Red Hat Enterprise")
    dnfnoup = ("No security updates")
    if strFedora in checkDistroNameStrL:
        #checks a fedora based system for security patches
        DNFcheckupdate=subprocess.run(['sudo dnf check-update --security'],shell=True, capture_output=True)
        DNFupdstdr=DNFcheckupdate.stderr.decode('utf-8')
        if dnfnoup in DNFupdstdr:
            print("no security updates available (DNF)")
            ll.append(lobj("No security updates (dnf)",10,1,6))
        else:
            print("Warning! Not all security updates are installed. Please run 'sudo dnf update --security'")
            ll.append(lobj("Warning: not up to date (dnf/fedora)",0,1,6))
    if strCentOS in checkDistroNameStrL:
        yumchkup=subprocess.run(['yum --security check-update'],shell=True,capture_output=True)
        ycustr=yumchkup.stdout.decode('utf-8')
        if dnfnoup in ycustr:
            print("No security updates available. (yum/centos)")
            ll.append(lobj("No security updates (yum/centos)",10,1,6))
        else:
            print("Warning! Not all security updates are installed. Please run 'sudo yum update --security")
            ll.append(lobj("Warning: not up to date (yum/centos)", 0, 1, 6))
    if strUbuntu in checkDistroNameStrL:
        #Ubuntu update check logic
        ubuntuChkU=subprocess.run(['sudo cat /var/lib/update-notifier/updates-available | grep "security updates"'],shell=True,capture_output=True)
        strUcU=ubuntuChkU.stdout.decode('utf-8')
        print (strUcU)
        try:
            updatesAvail = int(GetNumber(strUcU))
            if updatesAvail > 0:
                print ("Warning: security patches not current. Run 'apt-get upgrade' as root to remedy. (apt/ubuntu)")
                ll.append(lobj("Not up to date (apt/ubuntu)",0,1,6))
            if updatesAvail == 0:
                print("Security patches are current. (apt/ubuntu)")
                ll.append(lobj("Up to date. (apt/ubuntu)",10,1,6))

        except TypeError or ValueError:
            print("Security patches are current. (apt/ubuntu)")
            ll.append(lobj("Up to date. (apt/ubuntu)", 10, 1, 6))
    if strRHEL in checkDistroNameStrL:
        rhelchk=subprocess.run(['sudo yum --security | grep rpm'],shell=True, capture_output=True)
        rhelchkstr=rhelchk.stdout.decode('utf-8')
        strRPM=("rpm")
        if strRPM in rhelchkstr:
            print("Warning: security patches not current. Run 'sudo yum --security update' to remedy. (yum/rhel)")
            ll.append(lobj("System not up to date. (yum/rhel)",10,1,6))
        else:
            print("System appears to be up to date. (yum/rhel)")
            ll.append(lobj("System up to date. (yum/rhel)",0,1,6))






while run:
    # main loop
    print("Welcome to salsa , an open-source security analysis program")
    print("Please run this as a normal user! It's necessary in order to get correct results for some tests")
    mv = input(
        "Type 'network' or 'n' to connect to a server, 's'/'scan' to check this system for security holes, or 'x' to exit.\n")
    print(mv)
    if mv == ("s") or mv == ("scan"):
        ll.clear()
        CheckSecurity()
        finalize(ll,filename)
    if mv == ("n") or mv == ("network"):
        print("Sending security items to the server...")


        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 9848))
        r = s.recv(1024).decode('utf-8')
        received = r.split()
        print(r)
        for object in ll:
            hn=subprocess.run(['hostname'],capture_output=True,shell=True)
            hnstr=hn.stdout.decode('utf-8')
            s.send(('<HOST>'+hnstr).encode())
            time.sleep(.5)
            s.send(('<ID>'+str(object.id)).encode())
            time.sleep(.5)
            s.send(('<DESC>'+object.desc).encode())
            time.sleep(.5)
            s.send(('<DSS>'+str(object.dss)).encode())
            time.sleep(.5)
            s.send(('<SCORE>'+str(object.score)).encode())
            time.sleep(.5)
            s.send('<END>'.encode())

        #print ("sent")
        s.send("<EXIT>".encode())
        print("EXIT SENT")
        time.sleep(1)
        s.close()



    if mv == ("exit") or mv == ("x"):
        run = False
