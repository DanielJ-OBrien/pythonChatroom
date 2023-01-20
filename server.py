import socket
from _thread import *
import os
from cryptography.fernet import Fernet
import base64
import time
class serverMain():

    def __init__(self):
        
        #Prime, Base, and privNumver all used for encryption. Negotiated with Diffie-Hellman.
        self._publicPrime = 134715397998534382362543644062597181361609479648842843616200298096041989690697848999412391468700769363391823159719834719898132229523645517185214071033109009859909166224500832798606843889422676631533434306132458441957921028226184976216824642407273933750712043589484173533001512977046594666429936219284470523999
        self._publicBase = 2
        self._privateNumber = 13
        #User dictionaries. _Users holds a list of every user and their conn. When a user first connects the are in unverified. They get moved to verified when they log in.
        #They is kept separate so when sending a message, only people logged in can see it.
        self._unverifiedUsers = {}
        self._verifiedUsers = {}
        self._Users = {}
        #Fernets are stored with conns to send the correctly encrypted message to each user.
        self._Fernets = {}
        #Counters are an int stored with conn that holds a Unique ID for each packet sent.
        self._Counters = {}
        #Changes how the server behaves based upon if the user is logged in or not.
        self._loggedInState = False
        #Makes socket accessible to entire class.
        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def Broadcast(self, sentConn, command, message):
        #This function sends a message to every connected who has logged in.
        #It iterates though the verifieduser and fernet dictionaries, comparing with the called conn, to find correct values.
        #It then sends the correct values to the send data function.
        try:
            message = str(self._verifiedUsers.get(sentConn))+ ": " + message
            #Opens a text file and writes the message to it, before closing it again right after
            #This allows data to be saved between sessions.
            file1 = open("chatLog.txt","a+")
            file1.write(message+"\n")
            file1.close()
            for conn in self._verifiedUsers:
                if conn != sentConn:
                    holder = conn
                    for conn in self._Fernets:
                        if conn == holder:
                            try:
                                self.SendData(conn, command, message, self._Fernets.get(conn), False)
                            except Exception as e:
                                print(e)
                                pass
        except Exception as e:
            print(f"0. {e}")
            pass
        
    def ChangeUsername(self, conn, message):
        #Updates the display name of the user that used /nick with whatever they types. Strips whitespaces.
        try:
            message = message.replace(" ", "")
            self._verifiedUsers.update({conn: message})
        except Exception as e:
            print(f"1. {e}")
            pass


    def CalculateSecret(self, message, sent):
        #Function that calculates the 'secret' value used for encryption with the diffie-hellman exchange.
        try:
            return (pow(int(message),sent,self._publicPrime))
        except Exception as e:
            print(f"2. {e}")
            pass

    def ConvertFern(self, sharedKey):
        #Function that converts the shared secret to a fernet-friendly datatype for encryption with the diffie-hellman exchange.
        try:
            return base64.urlsafe_b64encode(f"{sharedKey:032d}".encode("utf-8")[:32])
        except Exception as e:
            print(f"3. {e}")
            pass
    
    def DecryptMessage(self, message, fernet):
        #Uses the passed fernet to decrypt a message recieved from the user and returns it to wherever called it.
        try:
            decodedMessage = fernet.decrypt(message)
            return decodedMessage
        except Exception as e:
            print(f"4. {e}")
            pass

    def Disconnect(self, conn, addr):
        #A function that iterates through each user dictionary, and remove any with the passed conn. It then closes the connection.
        try:
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
        except Exception as e:
            print(f"5. {e}")
            pass       

    def EncryptMessage(self, message, fernet):
        #Encrypts a message with the passed fernet and returns it to wherever called it.
        try:
            encryptedMessage = fernet.encrypt(bytes(message, encoding='utf8'))
            return encryptedMessage
        except Exception as e:
            print(f"6. {e}")
            pass

    def HandShake(self, conn, command, message):
        #Function that takes part in the 'handshake' of the diffie-hellman exchange. Only runs once per client. 
        #Does the maths required and sends it to the client and back to where it was called.
        try:
            message = pow(self._publicBase,self._privateNumber,self._publicPrime)
            sent = message
            self.SendData(conn, command, message, None, True)
            return sent
        except Exception as e:
            print(f"7. {e}")
            pass

    def Login(self, conn, message, fernet):
        #Runs during the not-logged-in state of the server. checks for if the user sent the pre-set password.
        #If they have, it sends the logged-in message to the client and changes the clients logged in state to True
        #If its incorrect, It just sends them an error message.
        try:
            if(message == "Password123"):
                self.SendData(conn, 3, "", fernet, False)
                time.sleep(1)
                self.SendData(conn, 2, "Password Correct. You can now chat with other people.", fernet, False)
                #Moves the user from unverified to verified dictionaries to send/recieve messages
                del self._unverifiedUsers[conn]
                self._verifiedUsers[conn] = "Guest"
            else:
                self.SendData(conn, 2, "Password Incorrect.", fernet, False)
        except Exception as e:
            print(f"8. {e}")
            pass
        
    def RetrieveChatLog(self, conn, fernet):
        #Uses a for loop to iterate over every line in the txt file, sending it to the user who requested the log.
        #Each line is also stripped to remove the line break.
        try:
            file1 = open("chatLog.txt","r")
            Lines = file1.readlines()
            for line in Lines:
                time.sleep(0.4)
                line = line.strip()
                self.SendData(conn, 2, line, fernet, False)
            file1.close()
        except Exception as e:
            print(f"9. {e}")
            pass
    
    def SendData(self, conn, command, message, fernet, special):
        #VERY important function. Sends a message to the passed conn.
        try:
            #Updates the PacketCount to ensure each ID is unique and inline with what the client expects.
            self.UpdatePacketCount(conn)
            #Gets the count of the relevant client.
            sentPacketID = self._Counters.get(conn)
            #Ensures the ID is 4 characters regardless of size.
            sentPacketIDString = "{:04}".format(sentPacketID)
            #Adds combines passed elements and adds !! as a format content check.
            message = str(sentPacketIDString) + str(command) + str(message) + str("!!")
            #Runs only once, when the public values are exchanged in diffie-hellman.
            if special == True:
                conn.send(message.encode("utf-8"))
                return
            #Encrypts the message, and sends it.
            message = self.EncryptMessage(message, fernet)
            conn.send(message)
        except Exception as e:
            print(f"10. {e}")
            pass
        
    def UpdatePacketCount(self, conn):
        #Increases the unique packet ID by one.
        current = self._Counters.get(conn)
        current+=1
        self._Counters.update({conn: current})

    def Main(self, conn, addr):
        #The main, threaded function.
        #Sets base values to 0
        sentPacketID=0
        recievedPacketID=0
        while True:
            if(conn in self._Users):
                try:
                    #Connects to the client
                    rData = conn.recv(1024).decode("utf-8")
                    #Increases the recieved packet ID. This makes sure the data packets recieved are legitimate.
                    recievedPacketID+=1
                    recievedPacketIDstring = "{:04}".format(recievedPacketID)
                    #These lines will always run, and pick out the useful parts of the package 
                    try:
                        try:
                            command = int(rData[4])
                        except:
                            command = rData[4]
                        message = rData[5:-2]
                        try:
                            #Runs when we have a fernet, and have to decrypt messages. SHould only not run on the first packet recieved, which gives the public value.
                            if fernet != None:
                                rData = self.DecryptMessage(rData, fernet)
                                rData = rData.decode()
                                sentId = rData[0:4]
                                suffix = rData[-2:]
                                command = int(rData[4])
                                message = rData[5:-2]
                                #Checks packet content. If the format or ID is wrong the connection is closed on suspicion of malicious messages.
                                if suffix != "!!" or sentId != recievedPacketIDstring:
                                    print("Invalid packet detected. Severing Connection.")
                                    self.Disconnect(conn, addr)
                        except Exception as e:
                            #print(f"11. {e}")
                            pass
                    except Exception as e:
                        print(f"12. {e}")
                        pass
                    #Matches the command recieved by the client to call the correct function.
                    match command:
                        case 0:
                            #Creates a variables for the fernet which is then stored in the dictionary.
                            sharedKey = self.CalculateSecret(message, sent)
                            fernet = Fernet(self.ConvertFern(sharedKey))
                            self._Fernets[conn] = fernet
                        case 1:                    
                            self.Broadcast(conn, 2, message)
                        case 2:
                            #Either tries to log you in or sends data, depending on the servers state.
                            if self._loggedInState == False:
                                self.Login(conn, message, fernet)
                            else:
                                self.SendData(conn, 2, message, fernet, False)
                        case 3:
                            self.ChangeUsername(conn, message[6:])
                        case 4:
                            try:
                                self.RetrieveChatLog(conn, fernet)
                            except Exception as e:
                                print(e)
                                pass
                except Exception as e:
                    #Calls for a disconnect when the main function encounters a significant error, disconnecting the user.
                    print(e)
                    self.Disconnect(conn, addr)
                    return

            else:
                #Runs if the user has never been seen before. This is done by checking the user dictionary.
                #It adds them to the correct dictionaries and begins the diffie-hellman key exchange.
                try:
                    print(f"New client registered: {addr}")
                    self._Users[conn] = "Guest"
                    self._unverifiedUsers[conn] = "Guest"
                    self._Counters[conn] = sentPacketID
                    sent = self.HandShake(conn, 0, "")
                except:
                    pass

    def RunServer(self):
        #Sets up basic sockets and threading.
        threadCount = os.cpu_count()
        hostName = socket.gethostname()
        HOST = socket.gethostbyname(hostName)
        PORT = 50001
        self._s.bind((HOST, PORT))
        self._s.listen()
        print(f"Listening on {(HOST, PORT)}")
        #Keeps looping. When a user connects, a new thread it created to listen for data.
        while True:
            try:
                conn, addr = self._s.accept()
                start_new_thread(self.Main, (conn, addr))
                    
            except KeyboardInterrupt:
                print("Caught keyboard interrupt, exiting")

if __name__ == "__main__":
    #Creates instance of main class and runs the starter function.
    client = serverMain()
    client.RunServer()