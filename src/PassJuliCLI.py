import csv
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
import os

ph=PasswordHasher()

class PasswordManager:
    masterpassword=None
    def __init__(self):
        print("Welcome to The Password Manager App by Saurab Parajuli")
        
        
    def loginVerifier(self,username,masterpassword):
        self.username=username
        self.masterpassword=masterpassword
        hashedpassword=None
        with open("registeredUsers.csv","r") as csvfile:
            csvreader=csv.DictReader(csvfile)
            for row in csvreader:
                if row["Username"] == self.username:
                    hashedpassword = row["Password"]
                    break
        if(hashedpassword is None):
            print("User not found ! ")
            continueVerification=True
            return continueVerification
        try:
            ph.verify(hashedpassword,self.masterpassword)
            print("Login Verified ! ")
            PasswordManager.masterpassword=self.masterpassword
            continueVerification=False
            return continueVerification
            
        except VerifyMismatchError:
            print("Password Error ! ")
            continueVerification=True
            return continueVerification
            
        except ValueError:
            print("User not found!")
            continueVerification=True
            return continueVerification
            
        
       
    def addNewPassword(self):
        website=input("Enter website : ")
        username=input("Enter username : ")
        password=input("Enter password : ")

        fieldnames=["website","username","password"]
        file_exists = os.path.exists("details.csv")
        with open("details.csv","a",newline='') as file:
            csvwriter=csv.DictWriter(file,fieldnames)
            if not file_exists:
                csvwriter.writeheader()
            csvwriter.writerow({"website":website,"username":username,"password":encrypt(self.masterpassword,password)})
        print("Saved ! ")
    
    def viewPasswords(self):
        try:
            with open("details.csv","r") as csvfile:
                csvreader=csv.DictReader(csvfile)
                for rows in csvreader:
                    encrypted_password=rows["Password"]
                    decrypted_password=decrypt(self.masterpassword,encrypted_password)
                    print(rows["Website"],rows["Username"],decrypted_password,rows["Notes"])
                    
        except StopIteration:
                print("No Saved Passwords found!")
                return
            
def RegisterPage():
    print("Welcome to the Register Page : ")
    username=input("Username: ")
    masterpassword=input("Password : ")
    fieldnames=["Username","Password"]
    with open("registeredUsers.csv","w",newline="") as csvfile:
        csvwriter=csv.DictWriter(csvfile,fieldnames=fieldnames)
        csvwriter.writeheader()
        csvwriter.writerow({"Username":username,"Password":HashMasterPassword(masterpassword)})
    print("User Registerd Successfully!")
    with open("details.csv","w",newline="") as csvfile:
        csvwriter=csv.DictWriter(csvfile,fieldnames=["website","username","password"])
        csvwriter.writeheader()
    frontPage()
    return True

def HashMasterPassword(masterPassword):
    hashedPassword=ph.hash(masterPassword)
    return hashedPassword

def loginPage():
   admin=PasswordManager()
   print("Welcome to the Login Page : ")
   username=input("Username: ")
   masterpassword=input("Password : ")
   continueVerification=admin.loginVerifier(username,masterpassword)
   return continueVerification

def get_key(masterpassword,salt):
    return PBKDF2(masterpassword,salt,dkLen=32,count=100000)

def encrypt(masterpassword,passwordToEncrypt):
    salt=os.urandom(16)
    key=get_key(masterpassword,salt)
    iv=os.urandom(12)
    cipher=AES.new(key,AES.MODE_GCM,iv)
    cipher_text,tag=cipher.encrypt_and_digest(passwordToEncrypt.encode("utf-8"))
    return base64.b64encode(salt+iv+tag+cipher_text).decode("utf-8")

def decrypt(masterpassword,encrypted_data):
    data=base64.b64decode(encrypted_data)
    salt,iv,tag,cipher_text=data[:16],data[16:28],data[28:44],data[44:]
    key=get_key(masterpassword,salt)
    cipher=AES.new(key,AES.MODE_GCM,nonce=iv)
    return cipher.decrypt_and_verify(cipher_text,tag).decode("utf-8")

continueRunningApp=True
continueVerification=True
def frontPage():
    print("1. To register a new user if no user exists ! ")
    print("2. To Login with an existing user ! ")
    command=int(input("Enter your choice : "))
    try:
        if(command==1):
            return RegisterPage()
        elif(command==2):
            return loginPage()
    except ValueError:
        print("Invalid value")
        frontPage()


admin=PasswordManager()
while(continueVerification):
    continueVerification=frontPage()

while (continueRunningApp):
    print("1. Add New Password . ")
    print("2. View  Passwords . ")
    print("3. Close the application ")
    command=int(input("Enter the number of command you wish to execute : "))
    if(command==1):
        admin.addNewPassword()
    elif(command==2):
        admin.viewPasswords()
    elif(command==3):
        continueRunningApp=False

