run = True
import subprocess
import pygame
def compareout2str(stdout,string):
    array1=[]
    array2=[]
    #This function is a hideously complex workaround because I can't compare stdout to a string for whatever reason
    for character in stdout:
        array1.append(character)
    for character in string:
        array2.append(character)
    print (array1)
    print (array2)




def CheckSecurity():
    finalscore = 0
    whoami = subprocess.run(["whoami"], stdout=subprocess.PIPE, universal_newlines=True)
    user = str(whoami.stdout)
    test = str("lprice")
    whoami=str(whoami)

    # This block of code determines if you're running as root. You shouldn't use the root account!
    if user == test:
        print("Warning: You appear to be running this program as root")
    else:
        print("not root")
        #this does not work- subprocess.run produces an object not a string
        #need to figure out how to compare the 2
        compareout2str(whoami,test)

    print(user)
    print(test)


while run:
    print("Welcome to (name plz) , an open-source security analysis program")
    mv = input(
        "Type 'network' or 'n' to connect to a server, 's'/'scan' to check this system for security holes, or 'x' to exit.")
    print(mv)
    if mv == ("s") or mv == ("scan"):
        CheckSecurity()

    if mv == ("exit") or mv == ("x"):
        run = False
