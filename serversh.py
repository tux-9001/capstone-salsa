
import socket
import tkinter as tk
import subprocess
import time
checkDistroName = subprocess.run(['cat /etc/*-release | grep PRETTY_NAME | head -1'], capture_output=True, shell=True)
# could simplify command
checkDistroNameStr = checkDistroName.stdout.decode('utf-8')
checkDistroNameStrL = checkDistroNameStr.strip()
def Setup():
    if 'Fedora' in checkDistroNameStrL or 'CentOS' in checkDistroNameStrL or 'Red Hat' in checkDistroNameStrL:
        subprocess.run(['sudo yum install tkinter'],shell=True,capture_output=True)
    if 'Debian' in checkDistroNameStrL or 'Ubuntu' in checkDistroNameStrL:
        subprocess.run(['sudo apt-get tkinter'],shell=True,capture_output=True)

run=True
a=subprocess.call(['python3 server-cli.py &'],shell=True)
print(a)
Setup()
def SAR(message):
    runF=True
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 9848))
    strL=[]
    while runF:
        #Sends and receives
        s.send(message.encode())
        r = s.recv(1024).decode('utf-8')
        received = r.strip()
        time.sleep(.5)
        if '<E>' in r:
            s.send('<EXIT>'.encode())
            runF=False
        eee=received.removesuffix('<E>')
        strL.append(eee)

    s.close()
    return strL

class GuiObj:
    def __init__(self,interface,string):
        #you should set the interface to root or whatever the main window is
        #the string is meant to display security objects
        self.label=tk.Label(interface,text=string)
    def render(self):
        self.label.pack()

while run:
    menuVar=input("Type 'c' to continue in CLI mode,'q' to quit, or 'g' to start the GUI.")
    if menuVar=='c':
        cliV=input("Type 'v' to view all security items or 'vh/(hostname) to view items for a specific hostname")
        if cliV == 'v':
            displ=SAR('<VIEW>ALL')
            for obj in displ:
                print(obj)
        if 'vh' in cliV:
            vr=cliV.removeprefix('vh/')
            displ=SAR(str('<VIEW>'+vr))
            for obj in displ:
                print(obj)
    if menuVar=='q':
        try:
            SAR('<QUIT>')
        except BrokenPipeError:
            pass
    def ViewAllGUI(gui):
        vli=SAR('<VIEW>ALL')
        l1=tk.Label(gui,text='Displaying all security info...')
        l1.pack()
        for obj in vli:
            label=tk.Label(gui,text=obj)
            label.pack()

    if menuVar=='g':
        root = tk.Tk()
        gvr=tk.StringVar()

        def ggvr2():
            global a
            a=textbox.get()
            print(a)
            l1=SAR('<VIEW>'+a)
            for obj in l1:
                label=tk.Label(root,text=obj)
                label.pack()



        def Quit():
            global run
            run=False
            root.quit()
            SAR('<QUIT>')

        guiL=[]
        viewButton=tk.Button(root,text="Click to view all security info.",command=lambda:ViewAllGUI(root))
        viewButton.pack()
        quitButton=tk.Button(root,text='Quit',command=Quit)
        quitButton.pack()
        sLabel=tk.Label(text="Search for a specific hostname")
        sLabel.pack()
        textbox=tk.Entry(root,width=20,textvariable=gvr)
        textbox.bind('<Return>',ggvr2())
        textbox.pack()
        sendButton=tk.Button(text="Go ->",command=ggvr2)
        sendButton.pack()
        print(a)



        root.mainloop()


