run = True
import subprocess
import pygame
log=open('log.txt' , 'w')
# PLEASE RUN THIS FROM TERMINAL, NOT PYCHARM!
# PYCHARM DOES *NOT* PROVIDE TERMINAL ACCESS!


def CheckSecurity():
    finalscore = 0
    class lobj:
        def __init__(self,desc,score):
            self.desc=desc
            self.score=score
            #Append to log[] list- this should determine final score
            #Will add these up at the end of security chk
            #Use desc value to describe why this score applies
    ll=[]
    #whoami = subprocess.run(["whoami"], stdout=subprocess.PIPE, universal_newlines=True)
    #user = str(whoami.stdout)
    #This ^ is the wrong way to get command output. leaving it for reference
    root = str("root\n")
    #whoami = subprocess.getoutput('sudo whoami',input=b'a')
    

    whoamir = subprocess.run(['whoami'], capture_output=True)
    print (whoamir)

    whoami=str(whoamir.stdout.decode("utf-8"))
    #This is the correct way to get the output of a command as a string

    if whoami == root:
        ll.append(lobj("Warning- Running as root!", -10))
        finalscore -= 10
        log.write("Check 1: Running as root\n")
        print("Running as root! This is a possible vulnerability")

    else:
        ll.append(lobj("Success- not root", 10))
        for obj in ll:
            print (obj.desc)
        log.write("Check 1: Not running as root\n")        #Backslash-n creates a new line

    #The above code determines if you're running this application as root
    print(root)
    print(whoami)


while run:
    print("Welcome to (name plz) , an open-source security analysis program")
    mv = input(
        "Type 'network' or 'n' to connect to a server, 's'/'scan' to check this system for security holes, or 'x' to exit.")
    print(mv)
    if mv == ("s") or mv == ("scan"):
        CheckSecurity()

    if mv == ("exit") or mv == ("x"):
        run = False



