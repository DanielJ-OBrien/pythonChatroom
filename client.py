import socket
import concurrent.futures
import time
from cryptography.fernet import Fernet
import base64
import random

class clientMain:
    
    publicPrime = 134715397998534382362543644062597181361609479648842843616200298096041989690697848999412391468700769363391823159719834719898132229523645517185214071033109009859909166224500832798606843889422676631533434306132458441957921028226184976216824642407273933750712043589484173533001512977046594666429936219284470523999
    publicBase = random.randint(1, 100)
    privateNumber = 29
    fernet = None

    def CalculateSecret(message, sent):
        return (pow(sent,int(message),clientMain.publicPrime))

    def ConvertFern(sharedKey):
        return base64.urlsafe_b64encode(f"{sharedKey:032d}".encode("utf-8")[:32])

    def DataProcessor():
        print("1")
        while True:
            try:
                rData = s.recv(1024).decode('utf-8')
                if fernet != None:
                    rData = clientMain.DecryptMessage(rData, fernet)
                    rData = rData.decode() 
                command = int(rData[0])
                message = rData[1:]
                match command:
                    case 0:
                        sharedKey = clientMain.HandShake(message)
                        fernet = Fernet(clientMain.ConvertFern(sharedKey))
                        print(fernet)
                    case 1:
                        clientMain.CalculateSecret(message)
                    case 2:
                        clientMain.DisplayMessage(message)
            except Exception as e:
                pass
        
    def DataSender():
        while True:
            try:
                time.sleep(1)
                uip = input()
                if uip[0] == "/":
                    clientMain.SendCommand(uip, clientMain.fernet)
                else:
                    try:
                        clientMain.SendBroadcast(uip, clientMain.fernet)
                    except Exception as e:
                        print(e)
            except:
                pass

    def DecryptMessage(message, fernet):
        decodedMessage = fernet.decrypt(message)
        return decodedMessage


    def DisplayMessage(message):
        print(message)

    def EncryptMessage(message, fernet):
        encryptedMessage = fernet.encrypt(bytes(message, encoding='utf8'))
        return encryptedMessage

    def HandShake(message2):
        message = pow(clientMain.publicBase,clientMain.privateNumber,clientMain.publicPrime)
        sent = message
        message = "0" + str(message)
        s.send((message).encode("utf-8"))
        key = clientMain.CalculateSecret(message2, sent)
        return key

    def SendBroadcast(message, fernet):
        message = "1" + message
        message = clientMain.EncryptMessage(message, fernet)
        s.send(message)

    def SendCommand(message, fernet):
        message = message[1:len(message)]
        message = clientMain.EncryptMessage(message, fernet)
        s.send(message)

hostname = socket.gethostname()
HOST = socket.gethostbyname(hostname)
PORT = 50001
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((HOST,PORT))
s.setblocking(0) 
threadPool = concurrent.futures.ThreadPoolExecutor(max_workers=4) 
test = clientMain()
try:
    threadPool.submit(test.DataProcessor)
    threadPool.submit(test.DataSender)
    while True:
        pass
except:
    print("Huge error")