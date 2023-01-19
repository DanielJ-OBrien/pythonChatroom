import sys
import socket
import types
from _thread import *
import os
from cryptography.fernet import Fernet
import base64
import random
import time
import queue

#Add proper disconnect handling on client side
class serverMain():

    def __init__(self):
        
        self._publicPrime = publicPrime = 134715397998534382362543644062597181361609479648842843616200298096041989690697848999412391468700769363391823159719834719898132229523645517185214071033109009859909166224500832798606843889422676631533434306132458441957921028226184976216824642407273933750712043589484173533001512977046594666429936219284470523999
        self._publicBase =  publicBase = 2
        self._privateNumber = privateNumber = 13
        self._unverifiedUsers = unverifiedUsers = {}
        self._verifiedUsers = verifiedUsers = {}
        self._Users = Users = {}
        self._Fernets = Fernets = {}
        self._loggedInState = loggedInState = False
        self._command = command = 0
        self._s = s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def Broadcast(self, sentConn, command, message):
        command = str(command) + str(self._verifiedUsers.get(sentConn))+ ": "
        message = str(command) + str(message)
        file1 = open("chatLog.txt","a+")
        file1.write(message[1:]+"\n")
        file1.close()
        for conn in self._verifiedUsers:
            if conn != sentConn:
                holder = conn
                for conn in self._Fernets:
                    if conn == holder:
                        try:
                            encryptedMessage = self.EncryptMessage(message, self._Fernets.get(conn))
                            conn.send(encryptedMessage)
                        except Exception as e:
                            print(e)
                            pass
        
    def ChangeUsername(self, conn, message):
        self._verifiedUsers.update({conn: message})


    def CalculateSecret(self, message, sent):
        return (pow(int(message),sent,self._publicPrime))

    def ConvertFern(self, sharedKey):
        return base64.urlsafe_b64encode(f"{sharedKey:032d}".encode("utf-8")[:32])
    
    def DecryptMessage(self, message, fernet):
        decodedMessage = fernet.decrypt(message)
        return decodedMessage

    def EncryptMessage(self, message, fernet):
        encryptedMessage = fernet.encrypt(bytes(message, encoding='utf8'))
        return encryptedMessage

    def HandShake(self, conn, command, message):
        message = pow(self._publicBase,self._privateNumber,self._publicPrime)
        sent = message
        message = str(command) + str(message)
        conn.send((message).encode("utf-8"))
        return sent

    def Login(self, conn, message, fernet):
        if(message == "Password123"):
            self.SendData(conn, 3, "", fernet)
            time.sleep(1)
            self.SendData(conn, 2, "Password Correct. You can now chat with other people.", fernet)
            del self._unverifiedUsers[conn]
            self._verifiedUsers[conn] = "Guest"
        else:
            self.SendData(conn, 2, "Password Incorrect.", fernet)

    def RetrieveChatLog(self, conn, fernet):
        file1 = open("chatLog.txt","r")
        Lines = file1.readlines()
        for line in Lines:
            time.sleep(0.5)
            line = line.strip()
            print(line)
            self.SendData(conn, 2, line, fernet)
        file1.close()

    def SendData(self, conn, command, message, fernet):
        message = str(command) + str(message)
        message = self.EncryptMessage(message, fernet)
        conn.send(message)

    def Main(self, conn, addr):
        while True:
            if(conn in self._Users):
                try:
                    #Connects to the client
                    rData = conn.recv(1024).decode("utf-8")
                    try:
                        if fernet != None:
                            rData = self.DecryptMessage(rData, fernet)
                            rData = rData.decode()
                    except Exception as e:
                        pass
                    command = int(rData[0])
                    message = rData[1:]
                    match command:
                        case 0:
                            sharedKey = self.CalculateSecret(message, sent)
                            fernet = Fernet(self.ConvertFern(sharedKey))
                            self._Fernets[conn] = fernet
                        case 1:
                            self.Broadcast(conn, 2, message)
                        case 2:
                            if self._loggedInState == False:
                                self.Login(conn, message, fernet)
                            else:
                                self.SendData(conn, 2, message, fernet)
                        case 3:
                            self.ChangeUsername(conn, message)
                        case 4:
                            try:
                                self.RetrieveChatLog(conn, fernet)
                            except Exception as e:
                                print(e)
                                pass
                except Exception as e:
                    print(f"User disconnected: {addr}")
                    for x in self._Users.copy():
                        if x == conn:
                                del self._Users[conn]
                                pass
                    for x in self._unverifiedUsers.copy():
                        if x == conn:
                                del self._unverifiedUsers[conn]
                                conn.close()
                                pass
                    for x in self._verifiedUsers.copy():
                        if x == conn:
                                del self._verifiedUsers[conn]
                                conn.close()
                                pass
                    return

            else:
                try:
                    print(f"New client registered: {addr}")
                    self._Users[conn] = "Guest"
                    self._unverifiedUsers[conn] = "Guest"
                    sent = self.HandShake(conn, 0, "")
                except:
                    pass

    def RunServer(self):       
        threadCount = os.cpu_count()
        hostName = socket.gethostname()
        HOST = socket.gethostbyname(hostName)
        PORT = 50001
        self._s.bind((HOST, PORT))
        self._s.listen()
        print(f"Listening on {(HOST, PORT)}")
        while True:
            try:
                conn, addr = self._s.accept()
                start_new_thread(self.Main, (conn, addr))
                    
            except KeyboardInterrupt:
                print("Caught keyboard interrupt, exiting")

if __name__ == "__main__":
    client = serverMain()
    client.RunServer()