import socket
import concurrent.futures
import time
from cryptography.fernet import Fernet
import base64
import random
from _thread import *
from threading import Thread

class ClientMain:
    
    def __init__(self):
        
        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._loggedInState = False
        self._fernet = None
        self._publicPrime = 134715397998534382362543644062597181361609479648842843616200298096041989690697848999412391468700769363391823159719834719898132229523645517185214071033109009859909166224500832798606843889422676631533434306132458441957921028226184976216824642407273933750712043589484173533001512977046594666429936219284470523999
        self._publicBase = random.randint(1, 100)
        self._privateNumber = 29

    def DataProcessor(self):
        while True:
            try:
                rData = self._s.recv(1024).decode('utf-8')
                if self._fernet != None:
                    rData = self.DecryptMessage(rData, self._fernet)
                    rData = rData.decode()
                command = int(rData[0])
                message = rData[1:]
                match command:
                    case 0:
                        sharedKey = self.HandShake(message)
                        self._fernet = Fernet(self.ConvertFern(sharedKey))
                    case 1:
                        self.CalculateSecret(message)
                    case 2:
                        self.DisplayMessage(message)
                    case 3:
                        self._loggedInState = True
            except Exception as e:
                #print(f"0. {e}")
                pass

    def DecryptMessage(self, message, fernet):
        decodedMessage = self._fernet.decrypt(message)
        return decodedMessage

    def HandShake(self, message2):
        try:
            message = pow(self._publicBase,self._privateNumber,self._publicPrime)
            sent = message
            message = "0" + str(message)
            self._s.send((message).encode("utf-8"))
            key = self.CalculateSecret(message2, sent)
        except Exception as e:
            print(f"1. {e}")
        return key

    def CalculateSecret(self, message, sent):
        return (pow(sent,int(message),self._publicPrime))

    def ConvertFern(self, sharedKey):
        return base64.urlsafe_b64encode(f"{sharedKey:032d}".encode("utf-8")[:32])   

    def DisplayMessage(self, message):
        print(message)
    
    def DataSender(self):
        #Sends messages when logged in
        while True:
            try:
                time.sleep(1)
                uip = input()
                try:
                    if self._loggedInState == True:
                        if uip[0] != "/":
                            self.SendBroadcast(uip, self._fernet)
                        elif uip[0:5] == "/nick":
                            self.SendUsername(uip, self._fernet)
                        elif uip[0:4] == "/log":
                            self.SendLogRequest(uip, self._fernet)
                    else:
                        #Sends password login attempts when not logged in
                        print("Logging in...")
                        self.SendPassword(uip, self._fernet)
                except Exception as e:
                    print(f"2. {e}")
            except:
                pass

    def EncryptMessage(self, message, fernet):
        encryptedMessage = self._fernet.encrypt(bytes(message, encoding='utf8'))
        return encryptedMessage

    def SendBroadcast(self, message, fernet):
        message = "1" + message
        message = self.EncryptMessage(message, self._fernet)
        self._s.send(message)
        
    def SendPassword(self, message, fernet):
        message = "2" + message
        message = self.EncryptMessage(message, self._fernet)
        self._s.send(message)
        
    def SendUsername(self, message, fernet):
        message = "3" + message
        message = self.EncryptMessage(message, self._fernet)
        self._s.send(message)
        
    def SendLogRequest(self, message, fernet):
        message = "4" + message
        message = self.EncryptMessage(message, self._fernet)
        self._s.send(message)

    def RunClient(self):
        hostname = socket.gethostname()
        HOST = socket.gethostbyname(hostname)
        PORT = 50001
        self._s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self._s.connect((HOST,PORT))
        self._s.setblocking(0) 
        try:
            thread1 = Thread(target = self.DataProcessor, args =())
            thread2 = Thread(target = self.DataSender, args =())
            thread1.start()
            thread2.start()
            while True:
                pass
        except Exception as e:
            print("Huge error")
            print(e)
    
if __name__ == "__main__":
    client = ClientMain()
    client.RunClient()