run = True
import subprocess




class lobj:
    def __init__(self, desc, score, dss, id):
        self.desc = desc
        self.score = score
        self.dss = dss
        self.id = id
        # Append to log[] list- this should determine final score
        # Will add these up at the end of security chk
        # Use desc value to describe why this score applies
        # The "dss" variable exists to make PCI-DSS compliance auditing easier- sysadmins should be able to use this to audit dss compliance

# PLEASE RUN THIS FROM TERMINAL, NOT PYCHARM!
# PYCHARM DOES *NOT* PROVIDE TERMINAL ACCESS!
def finalize(array):
    #compiles a report


        filename=""
        ovwr=""
        checkls=subprocess.run(['ls'],capture_output=True,shell=True)
        checklsstr=checkls.stdout.decode("utf-8")
        frun=True
        while frun:
            filename=input("Please enter a name for the logfile\n")
            if filename in checklsstr:
                ovwr=input ("Warn: a file appears to exist under this name. Overwrite?")
            if ovwr == "y":
                log = open(filename, 'w')
                frun=False
            if filename not in checklsstr:
                log = open(filename, 'w')
                frun=False
        for lobj in array:
            print (lobj.desc)
            print (lobj.id)
            print (lobj.dss)
            print (lobj.score)
                #TODO: Finish building this
            log.write(lobj.desc)
            log.write(" ")
            log.write(str(lobj.id))
            log.write(" ")
            log.write(str(lobj.dss))
            log.write(" ")
            log.write(str(lobj.score))
            log.write("\n")


        log = open(filename, 'w')
ll = []

def CheckSecurity():
    finalscore = 0


    # whoami = subprocess.run(["whoami"], stdout=subprocess.PIPE, universal_newlines=True)
    # user = str(whoami.stdout)
    # This ^ is the wrong way to get command output. leaving it for reference
    root = str("root\n")
    # whoami = subprocess.getoutput('sudo whoami',input=b'a')

    # log.write("Check 1: Not running as root\n")
    # Backslash-n creates a new line
    # The above code determines if you're running this application as root
    # print(root)
    # print(whoami)
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
        ll.append(lobj("Warning- root login enabled via SSH", -10, 0, 1))
        print("Warning- root login enabled via SSH. This opens your root account to bruteforce attacks over SSH.")
    selinuxenf = subprocess.run(['getenforce | head -n 1'], capture_output=True, shell=True)
    selinuxenfstr = selinuxenf.stdout.decode("utf-8")
    strEnforcing = ("Enforcing")
    strPermissive = ("Permissive")
    # TODO: Check for DSS compliance and categorize it separately from the standard security scan
    # TODO: check this article for info: https://linux-audit.com/linux-systems-guide-to-achieve-pci-dss-compliance-and-certification/#the-auditor-friend-or-foe
    # I'll need to use a VM to check for this as it involves enabling insecure services
    if strEnforcing in selinuxenfstr:
        print("SELinux is set to enforcing. This makes it more difficult for malicious actors to modify files.")
        ll.append(lobj("Success- SELinux enforcing", 10, 0, 2))
    if strPermissive in selinuxenfstr:
        print("SELinux is set to permissive- this doesn't prevent violations!")
        print("To set SELinux to enforcing, run 'sudo setenforce 1'.")
        ll.append(lobj("Warning- SELinux is set to permissive!", -10, 0, 2))
        # Checks SELinux status
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
        if sslcheckstr not in vssec:
            print("Warning: FTP service is running in cleartext mode")
            ll.append(lobj("FTP on and insecure", -10, 1, 3))
        if sslcheckstr in vssec:
            print("VSFTPD is enabled and secured.")
            ll.append(lobj("VSFTPD secured.", 10, 1, 3))
    else:
        print("FTP appears to be disabled.")
        ll.append(lobj("FTP off", 10, 1, 3))
        # Checks FTP security
    checkfirewall = subprocess.run(['lsmod | grep table'], capture_output=True, shell=True)
    checkfirewallstr = checkfirewall.stdout.decode("utf-8")
    nftablesstr = ("nf_tables")
    iptablesstr = ("ip_tables")
    print(checkfirewallstr)
    if nftablesstr in checkfirewallstr:
        # Checks if firewall is enabled
        print("nftables enabled. Please ensure that it's configured correctly")
        ll.append(lobj("Firewall enabled. Check cfg", 10, 1, 4))
    if iptablesstr in checkfirewallstr:
        print("iptables enabled. Please ensure that it's configured correctly")
        ll.append(lobj("Firewall enabled. Check cfg", 10, 1, 4))
    else:
        print("Warning: no firewall detected! This is a major security risk")
        ll.append(lobj("Warning: no firewall", -10, 1, 4))


while run:
    # main loop
    print("Welcome to salsa , an open-source security analysis program")
    print("Please run this as a normal user! It's necessary in order to get correct results for some tests")
    mv = input(
        "Type 'network' or 'n' to connect to a server, 's'/'scan' to check this system for security holes, or 'x' to exit.")
    print(mv)
    if mv == ("s") or mv == ("scan"):
        CheckSecurity()
        finalize(ll)
    if mv == ("n") or mv == ("network"):
        print("Not implemented yet!")
        # TODO: Networking code for connection to server
    if mv == ("exit") or mv == ("x"):
        run = False
