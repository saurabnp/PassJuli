import os,csv
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, QTextEdit, QPushButton,QHBoxLayout, QLabel, QTableWidgetItem, QMessageBox,QMenu,QMainWindow,QApplication,QHeaderView
)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from PyQt6 import QtWidgets, uic,QtCore
from PyQt6.QtGui import QClipboard, QAction,QFont
from appdata import resource_path,get_appdata_path
from showPasswords import PasswordPage
ph = PasswordHasher()

class FrontPage(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()
        uic.loadUi(resource_path("../ui/GUIforPM.ui"), self)
        
        self.login_button.clicked.connect(self.login_function)
        self.register_button.clicked.connect(self.register_function)
        self.eyeIcon.clicked.connect(self.toggle_password_visibility)

    def toggle_password_visibility(self):
        """Toggle password visibility between hidden and shown."""
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.eyeIcon.setText("🙈 Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.eyeIcon.setText("👁 Show")
    
    def login_function(self):
        username = self.username_input.text()
        password = self.password_input.text()
        hashedPassword = None
        try:
            with open(os.path.join(get_appdata_path(), "registeredUsers.csv"), "r") as csvfile:
                csvreader = csv.DictReader(csvfile)
                for details in csvreader:
                    if details["Username"] == username:
                        hashedPassword = details["Password"]
                        break
        except FileNotFoundError:
            QMessageBox.warning(self, "Register a User First")
            return
        if hashedPassword is None:
            QMessageBox.warning(self, "Login Failed", "User not found!")
            return
        
        try:
            ph.verify(hashedPassword, password)
            
            self.open_password_manager(password)
        except VerifyMismatchError:
            QMessageBox.warning(self, "Login Failed", "Invalid password!")

    def open_password_manager(self,masterPassword):
        self.password_page = PasswordPage(masterPassword)
        self.password_page.show()
        self.close()

    def register_function(self):
        username = self.username_input.text()
        password = self.password_input.text()
        hashedPassword = ph.hash(password)
        fieldnames = ["Username", "Password"]
        
        with open(os.path.join(get_appdata_path(),"registeredUsers.csv"), "w", newline='') as csvfile:
            csvwriter = csv.DictWriter(csvfile, fieldnames=fieldnames)
            csvwriter.writeheader()
            csvwriter.writerow({"Username": username, "Password": hashedPassword})
        
        with open(os.path.join(get_appdata_path(),"details.csv"), "w") as csvfile:
            print("Details.csv file was reset.")

        msg = QMessageBox()
        msg.setWindowTitle("Registration Successful")
        msg.setText("User Registered Successfully! Now Login to continue.")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()

