import sys
import socket
import types
import concurrent.futures
import os
from cryptography.fernet import Fernet
import base64
import random

#Add proper disconnect handling on client side
#Add simple login system (2+ distinct states for a pass)
#Allow logins to be saved between server runs ()
#implement proper class usage

class serverMain:

    publicPrime = 134715397998534382362543644062597181361609479648842843616200298096041989690697848999412391468700769363391823159719834719898132229523645517185214071033109009859909166224500832798606843889422676631533434306132458441957921028226184976216824642407273933750712043589484173533001512977046594666429936219284470523999
    publicBase = 2
    privateNumber = 13
    Users = {}
    Fernets = {}
    command = 0

    def Broadcast(sentConn, command, message):
        command = str(command) + str(serverMain.Users.get(sentConn))+ ": "
        message = str(command) + str(message)
        for conn in serverMain.Users:
            if conn != sentConn:
                holder = conn
                for conn in serverMain.Fernets:
                    if conn == holder:
                        try:
                            encryptedMessage = serverMain.EncryptMessage(message, serverMain.Fernets.get(conn))
                            conn.send(encryptedMessage)
                        except Exception as e:
                            print(e)
                            pass
        
    def ChangeUsername(conn, message):
        serverMain.Users.update({conn: message})


    def CalculateSecret(message, sent):
        return (pow(int(message),sent,serverMain.publicPrime))

    def ConvertFern(sharedKey):
        return base64.urlsafe_b64encode(f"{sharedKey:032d}".encode("utf-8")[:32])
    
    def DecryptMessage(message, fernet):
        decodedMessage = fernet.decrypt(message)
        return decodedMessage

    def EncryptMessage(message, fernet):
        encryptedMessage = fernet.encrypt(bytes(message, encoding='utf8'))
        return encryptedMessage

    def HandShake(conn, command, message):
        message = pow(serverMain.publicBase,serverMain.privateNumber,serverMain.publicPrime)
        sent = message
        message = str(command) + str(message)
        conn.send((message).encode("utf-8"))
        return sent

    def SendData(conn, command, message, fernet):
        message = str(command) + str(message)
        message = serverMain.EncryptMessage(message, fernet)
        conn.send((message).encode("utf-8"))

    def Main():
        while True:
            conn, addr = s.accept()
            while True:
                if(conn in serverMain.Users):
                    try:
                        #Connects to the client
                        rData = conn.recv(1024).decode("utf-8")
                        try:
                            if fernet != None:
                                rData = serverMain.DecryptMessage(rData, fernet)
                                rData = rData.decode()  
                        except Exception as e:
                            pass
                        command = int(rData[0])
                        message = rData[1:]
                        match command:
                            case 0:
                                sharedKey = serverMain.CalculateSecret(message, sent)
                                fernet = Fernet(serverMain.ConvertFern(sharedKey))
                                serverMain.Fernets[conn] = fernet
                            case 1:
                                serverMain.Broadcast(conn, 2, message)
                            case 2:
                                serverMain.SendData(conn, 2, message, fernet)
                            case 3:
                                serverMain.ChangeUsername(conn, message)
                    
                    except Exception as e:
                        #Closes connection if it fails
                        for x in serverMain.Users:
                            if x == conn:
                                del serverMain.Users[conn]
                                conn.close()
                                print("Connection closed due to: ")
                                print(e)
                                pass
                else:
                    print(f"New client registered: {addr}")
                    serverMain.Users[conn] = "Guest"
                    sent = serverMain.HandShake(conn, 0, "")

threadCount = os.cpu_count()
hostname = socket.gethostname()
HOST = socket.gethostbyname(hostname)
PORT = 50001
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()
print(f"Listening on {(HOST, PORT)}")
threadPool = concurrent.futures.ThreadPoolExecutor(threadCount)
try:
    for x in range(0,threadCount):
        threadPool.submit(serverMain.Main)
    while True:
        pass
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")


