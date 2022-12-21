import socket
import concurrent.futures
import time
from cryptography.fernet import Fernet
import base64
import random

class ClientMain:
    
    fernet = None
    
class DataProcessorClass(ClientMain):
    publicPrime = 134715397998534382362543644062597181361609479648842843616200298096041989690697848999412391468700769363391823159719834719898132229523645517185214071033109009859909166224500832798606843889422676631533434306132458441957921028226184976216824642407273933750712043589484173533001512977046594666429936219284470523999
    publicBase = random.randint(1, 100)
    privateNumber = 29

    def DataProcessor():
        while True:
            try:
                rData = s.recv(1024).decode('utf-8')
                if ClientMain.fernet != None:
                    rData = DataProcessorClass.DecryptMessage(rData, ClientMain.fernet)
                    rData = rData.decode() 
                command = int(rData[0])
                message = rData[1:]
                match command:
                    case 0:
                        sharedKey = DataProcessorClass.HandShake(message)
                        ClientMain.fernet = Fernet(DataProcessorClass.ConvertFern(sharedKey))
                    case 1:
                        DataProcessorClass.CalculateSecret(message)
                    case 2:
                        DataProcessorClass.DisplayMessage(message)
            except Exception as e:
                pass

    def DecryptMessage(message, fernet):
        decodedMessage = fernet.decrypt(message)
        return decodedMessage

    def HandShake(message2):
        try:
            message = pow(DataProcessorClass.publicBase,DataProcessorClass.privateNumber,DataProcessorClass.publicPrime)
            sent = message
            message = "0" + str(message)
            s.send((message).encode("utf-8"))
            key = DataProcessorClass.CalculateSecret(message2, sent)
        except Exception as e:
            print(e)
        return key

    def ConvertFern(sharedKey):
        return base64.urlsafe_b64encode(f"{sharedKey:032d}".encode("utf-8")[:32])   

    def CalculateSecret(message, sent):
        return (pow(sent,int(message),DataProcessorClass.publicPrime))
    
    def DisplayMessage(message):
        print(message)


class DataSenderClass(ClientMain):
    
    def DataSender():
        while True:
            try:
                time.sleep(1)
                uip = input()
                if uip[0] == "/":
                    DataSenderClass.SendCommand(uip, ClientMain.fernet)
                else:
                    try:
                        DataSenderClass.SendBroadcast(uip, ClientMain.fernet)
                    except Exception as e:
                        print(e)
            except:
                pass
            
    def EncryptMessage(message, fernet):
        encryptedMessage = fernet.encrypt(bytes(message, encoding='utf8'))
        return encryptedMessage



    def SendBroadcast(message, fernet):
        message = "1" + message
        message = DataSenderClass.EncryptMessage(message, fernet)
        s.send(message)

    def SendCommand(message, fernet):
        message = message[1:len(message)]
        message = DataSenderClass.EncryptMessage(message, fernet)
        s.send(message)

hostname = socket.gethostname()
HOST = socket.gethostbyname(hostname)
PORT = 50001
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((HOST,PORT))
s.setblocking(0) 
threadPool = concurrent.futures.ThreadPoolExecutor(max_workers=4) 
try:
    threadPool.submit(DataProcessorClass.DataProcessor)
    threadPool.submit(DataSenderClass.DataSender)
    while True:
        pass
except Exception as e:
    print("Huge error")
    print(e)