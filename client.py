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
        
        #Socket info stored for all functions to access.
        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #Stores the calculated fernet.
        self._fernet = None
        #Values used for diffie-hellamn key exchange and encryption.
        self._publicPrime = 134715397998534382362543644062597181361609479648842843616200298096041989690697848999412391468700769363391823159719834719898132229523645517185214071033109009859909166224500832798606843889422676631533434306132458441957921028226184976216824642407273933750712043589484173533001512977046594666429936219284470523999
        self._publicBase = random.randint(1, 100)
        self._privateNumber = 29
        #Booleans used to change how the client acts based upon state.
        self._loggedInState = False
        self._connected = False
        self._stop = False
        #Variables to keep track of unique packet IDs.
        self._sentPacketID = 0
        self._sentPacketIDString = ""
        self._recievedPacketID = -1
        self._recievedPacketIDString = ""

    def DataProcessor(self):
        #The first of two threaded function. This is always looping to recieve and process packets sent to the client.
        while True:
            try:
                #Returns to loses the thread if _stop is true, used for when reconnecting to server without errors or restarts.
                if self._stop == True:
                    return
                #Recieves data and increased the recieved packet count ID.
                rData = self._s.recv(1024).decode('utf-8')
                self._recievedPacketID+=1
                self._recievedPacketIDstring = "{:04}".format(self._recievedPacketID)
                #Same as the server, these lines will always run and pick out the useful parts of the package 
                try:
                    command = int(rData[4])
                except:
                    command = rData[4]
                message = rData[5:-2]
                try:
                     #Runs when we have a fernet, and have to decrypt messages. SHould only not run on the first packet recieved, which gives the public value.
                    if self._fernet != None:
                        rData = self.DecryptMessage(rData, self._fernet)
                        rData = rData.decode()
                        sentId = rData[0:4]
                        suffix = rData[-2:]
                        command = int(rData[4])
                        message = rData[5:-2]
                        #Checks packet content. If the format or ID is wrong the connection is closed on suspicion of malicious messages.
                        if suffix != "!!" or sentId != self._recievedPacketIDstring:
                            print("Invalid packet detected. Severing Connection.")
                            return
                except Exception as e:
                    #print(f"11. {e}")
                    pass
                #Matches the command recieved by the client to call the correct function.
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
        #Uses the passed fernet to decrypt a message recieved from the user and returns it to wherever called it.
        try:
            decodedMessage = self._fernet.decrypt(message)
            return decodedMessage
        except Exception as e:
            print(f"1. {e}")
            pass
        
    def HandShake(self, message2):
        #Function that takes part in the 'handshake' of the diffie-hellman exchange. Only runs once. 
        #Does the maths required and sends it to the client and back to where it was called.
        try:
            message = pow(self._publicBase,self._privateNumber,self._publicPrime)
            sent = message
            self.SendEncryptedMessage(message, 0, True)
            key = self.CalculateSecret(message2, sent)
            return key
        except Exception as e:
            print(f"2. {e}")
            pass

    def CalculateSecret(self, message, sent):
        #Function that calculates the 'secret' value used for encryption with the diffie-hellman exchange.
        try:
            return (pow(sent,int(message),self._publicPrime))
        except Exception as e:
            print(f"3. {e}")
            pass
        
    def ConvertFern(self, sharedKey):
        #Function that converts the shared secret to a fernet-friendly datatype for encryption with the diffie-hellman exchange.
        try:
            return base64.urlsafe_b64encode(f"{sharedKey:032d}".encode("utf-8")[:32])   
        except Exception as e:
            print(f"4. {e}")
            pass
        
    def DisplayMessage(self, message):
        #Prints the passed message
        try:
            print(message)
        except Exception as e:
            print(f"5. {e}")
            pass   

    def DataSender(self):
        #The second threaded function. This one allows user input to the console for sending messages.
        print("Insert password to continue.")
        while True:
            try:
                #Closes the thread if told to stop.
                if self._stop == True:
                    return
                #Prevents spam.
                time.sleep(1)
                uip = input()
                try:
                    #Checks to see if the login state is True. If it is, it will send a message depending upon what the user wrote, or error for an invalid command
                    if self._loggedInState == True:
                        if uip[0] != "/":
                            self.SendEncryptedMessage(uip, 1, False)
                        elif uip[0:5] == "/nick":
                            self.SendEncryptedMessage(uip, 3, False)
                        elif uip[0:4] == "/log":
                            self.SendEncryptedMessage(uip, 4, False)
                        else:
                            print("Invalid command.")
                    #If not logged in, it sends messages with command '2'. This is read as a login attempt on the server side.
                    else:
                        #Sends password login attempts when not logged in
                        print("Logging in...")
                        self.SendEncryptedMessage(uip, 2, False)
                except Exception as e:
                    #If sending the message fails, it is assumed the server has disconnected. This sets the states to False again and closes the thread.
                    print("Message failed due to server disconnect.")
                    self._loggedInState = False
                    self._connected = False
                    return
            except:
                pass

    def EncryptMessage(self, message):
        #Encrypts a message with the fernet and returns it to wherever called it.
        try:
            encryptedMessage = self._fernet.encrypt(bytes(message, encoding='utf8'))
            return encryptedMessage
        except Exception as e:
            print(f"6. {e}")
            pass
    
    def SendEncryptedMessage(self, message, case, special):
        #VERY important function. Sends a message to the server.
        #Updates the sentPacketID to ensure each ID is unique and inline with what the client expects.
        self._sentPacketID+=1
        #Ensures the ID is 4 characters regardless of size.
        self._sentPacketIDString = "{:04}".format(self._sentPacketID)
        #Correctly formats the message as the server expects.
        message = str(self._sentPacketIDString) + str(case) + str(message) + str("!!")
        #Runs only once, when the public values are exchanged in diffie-hellman.
        if special == True:
            self._s.send(message.encode("utf-8"))
            return
        #Encrypts the message, and sends it.
        message = self.EncryptMessage(message)
        self._s.send(message)

    def RunClient(self):
        #The starting function
        while True:
            try:
                #Attempts standard socket connection activities. If it succeeds, it ensures all values are returned to their default for a new server connection.
                hostname = socket.gethostname()
                HOST = socket.gethostbyname(hostname)
                PORT = 50001
                self._s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                self._s.connect((HOST,PORT))
                self._s.setblocking(0)
                self._connected = True
                self._stop = False
                self._loggedInState = False
                self._fernet = None
                self._sentPacketID = 0
                self._sentPacketIDString = ""
                self._recievedPacketID = 0
                self._recievedPacketIDString = ""
                while True:
                    #Creates threads for the data processor and reciever.
                    try:
                        thread1 = Thread(target = self.DataProcessor, args =())
                        thread2 = Thread(target = self.DataSender, args =())
                        thread1.start()
                        thread2.start()
                        #Loops to prevents new threads being made. Breaks if there has been a problem with the connection.
                        while True:
                            if self._connected == True:
                                pass
                            else:
                                break
                        self._stop = True
                        break
                    except Exception as e:
                        #Prints the connection error to the user and waits 5 seconds. Also sets _stop to true to ensure threads are closed.
                        print(f"8. {e}")
                        self._stop = True
                        time.sleep(5)
            except Exception as e:
                #Loops every 5 seconds, attempting to reconnect to the server without errors or restarts.
                print("Attempting to reconnect...")
                time.sleep(5)
                pass
    
if __name__ == "__main__":
    #Creates instance of the client class and runs the connection function.
    client = ClientMain()
    client.RunClient()