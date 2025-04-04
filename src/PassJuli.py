import csv,os,base64,secrets,string,sys
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, QTextEdit, QPushButton,QHBoxLayout, QLabel, QTableWidgetItem, QMessageBox,QMenu,QMainWindow,QApplication,QHeaderView
)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from PyQt6 import QtWidgets, uic,QtCore
from PyQt6.QtGui import QClipboard, QAction,QFont

# Initialize Argon2 Password Hasher
ph = PasswordHasher()

def resource_path(relative_path):
    """Get absolute path to resource, works for development and for PyInstaller"""
    try:
        base_path = sys._MEIPASS  # This is set by PyInstaller
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def get_appdata_path():
    """Returns the path to the AppData folder of the current user, specifically for your application."""
    app_name = "PassJuli"
    appdata = os.getenv('APPDATA')
    if not appdata:
        appdata = os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming')
    appdata_folder = os.path.join(appdata, app_name)
    
    if not os.path.exists(appdata_folder):
        os.makedirs(appdata_folder)
    
    return appdata_folder

# Function to derive encryption key from master password
def get_key(masterpassword, salt):
    return PBKDF2(masterpassword, salt, dkLen=32, count=100000)

# Encrypt function
def encrypt(masterpassword, passwordToEncrypt):
    salt = os.urandom(16)
    key = get_key(masterpassword, salt)
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(passwordToEncrypt.encode("utf-8"))
    return base64.b64encode(salt + iv + tag + ciphertext).decode("utf-8")

# Decrypt function
def decrypt(masterpassword, encryptedPassword):
    passwordToDecrypt = base64.b64decode(encryptedPassword)
    salt, iv, tag, ciphertext = passwordToDecrypt[:16], passwordToDecrypt[16:28], passwordToDecrypt[28:44], passwordToDecrypt[44:]
    key = get_key(masterpassword, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")

# Front Page (Login & Registration)
class FrontPage(QtWidgets.QMainWindow):
    master_password = None  # Global master password

    def __init__(self):
        super().__init__()
        uic.loadUi(resource_path("GUIforPM.ui"), self)
        
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
            FrontPage.master_password = password  # Store master password
            self.open_password_manager()
        except VerifyMismatchError:
            QMessageBox.warning(self, "Login Failed", "Invalid password!")

    def open_password_manager(self):
        self.password_page = PasswordPage()
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


# Password Manager Page
class PasswordPage(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi(resource_path("password.ui"), self)
        self.passwordTable.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.passwordTable.setColumnWidth(0, int(self.passwordTable.width() * 0.3))
        self.passwordTable.setColumnWidth(1, int(self.passwordTable.width() * 0.2))
        self.passwordTable.setColumnWidth(2, int(self.passwordTable.width() * 0.2))
        self.passwordTable.setColumnWidth(3, int(self.passwordTable.width() * 0.3))
        self.actual_passwords = {}
        self.loadCSV(os.path.join(get_appdata_path(),"details.csv"))
        self.addEntryButton.clicked.connect(self.addEntry)
        
        # Enable right-click context menu
        self.passwordTable.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.passwordTable.customContextMenuRequested.connect(self.show_context_menu)

    def show_context_menu(self, position):
        """Show right-click context menu to copy actual password."""
        menu = QtWidgets.QMenu(self)

        copy_action = QAction("Copy", self)
        copy_action.triggered.connect(self.copy_selected_cell)

        menu.addAction(copy_action)
        menu.exec(self.passwordTable.viewport().mapToGlobal(position))

    def copy_selected_cell(self):
        """Copy the selected cell's text to clipboard, handling masked passwords correctly."""
        selected_items = self.passwordTable.selectedItems()
        
        if selected_items:
            selected_item = selected_items[0]
            row = selected_item.row()
            col = selected_item.column()

            clipboard = QtWidgets.QApplication.clipboard()

            # Check if it's the Password column (index 2)
            if col == 2 and row in self.actual_passwords:
                clipboard.setText(self.actual_passwords[row])  # Copy actual password
            else:
                clipboard.setText(selected_item.text())  # Copy normal text


    def loadCSV(self, file_path):
        master_password = FrontPage.master_password
        self.passwordTable.setRowCount(0)

        if not os.path.exists(file_path):
            with open(file_path, "w", newline="", encoding="utf-8") as file:
                csvwriter = csv.writer(file)
                headers = ["Website", "Username", "Password", "Notes"]
                csvwriter.writerow(headers)
            return

        with open(file_path, "r", encoding="utf-8") as file:
            csvreader = csv.reader(file)
            try:
                headers = next(csvreader)
                self.passwordTable.setColumnCount(len(headers))
                self.passwordTable.setHorizontalHeaderLabels(headers)

                for row_index, row_data in enumerate(csvreader):
                    self.passwordTable.insertRow(row_index)

                    for col_index, col_data in enumerate(row_data):
                        if headers[col_index] == "Password" and col_data:
                            try:
                                decrypted_password = decrypt(master_password, col_data)  # Decrypt password
                                self.actual_passwords[row_index] = decrypted_password  # Store actual password
                                col_data = "********"  # Mask password
                            except Exception as e:
                                print(f"Decryption failed: {e}")
                        
                        item = QTableWidgetItem(col_data)
                        item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)  # Make cell non-editable
                        self.passwordTable.setItem(row_index, col_index, item)

            except StopIteration:
                headers = ["Website", "Username", "Password", "Notes"]
                self.passwordTable.setColumnCount(len(headers))
                self.passwordTable.setHorizontalHeaderLabels(headers)


    def addEntry(self):
        """Use a dialog to collect new password entry."""
        dialog = AddEntryDialog()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            site = dialog.title_input.text()
            username = dialog.username_input.text()
            password = dialog.password_input.text()
            notes = dialog.notes_input.toPlainText()

            if site and username and password:
                row_position = self.passwordTable.rowCount()
                self.passwordTable.insertRow(row_position)

                self.actual_passwords[row_position] = password

                self.passwordTable.setItem(row_position, 0, QTableWidgetItem(site))
                self.passwordTable.setItem(row_position, 1, QTableWidgetItem(username))
                self.passwordTable.setItem(row_position, 2, QTableWidgetItem("********"))
                self.passwordTable.setItem(row_position, 3, QTableWidgetItem(notes))
                self.save_to_csv(os.path.join(get_appdata_path(),"details.csv"))

    def save_to_csv(self, file_path):
        """Save only new unique data to CSV by comparing plaintext, and encrypting passwords before saving."""
        fieldnames = [self.passwordTable.horizontalHeaderItem(i).text() for i in range(self.passwordTable.columnCount())]
        master_password = FrontPage.master_password

        existing_data = set()

        # Step 1: Load existing CSV file to avoid duplicates
        if os.path.exists(file_path) and os.stat(file_path).st_size > 0:
            with open(file_path, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    plain_password = ""  # You can't decrypt without a key, so we'll skip password here
                    data_tuple = (
                        row.get("Website", "").strip(),
                        row.get("Username", "").strip(),
                        row.get("Notes", "").strip()
                    )
                    existing_data.add(data_tuple)

        # Step 2: Open CSV for appending new data
        file_exists = os.path.exists(file_path)
        file_empty = os.stat(file_path).st_size == 0 if file_exists else True

        with open(file_path, "a", newline="", encoding="utf-8") as file:
            csvwriter = csv.DictWriter(file, fieldnames=fieldnames)

            # Write header if file is empty
            if not file_exists or file_empty:
                csvwriter.writeheader()

            for row in range(self.passwordTable.rowCount()):
                # Collect raw data (excluding password for duplicate checking)
                website = self.passwordTable.item(row, 0).text() if self.passwordTable.item(row, 0) else ""
                username = self.passwordTable.item(row, 1).text() if self.passwordTable.item(row, 1) else ""
                notes = self.passwordTable.item(row, 3).text() if self.passwordTable.item(row, 3) else ""

                raw_tuple = (website.strip(), username.strip(), notes.strip())

                if raw_tuple in existing_data:
                    continue  # Skip duplicate entry

                # Encrypt and save the row
                row_data = {}
                for col in range(self.passwordTable.columnCount()):
                    column_name = fieldnames[col]
                    item = self.passwordTable.item(row, col)
                    value = item.text() if item else ""

                    if column_name == "Password":
                        value = encrypt(master_password, self.actual_passwords.get(row, ""))

                    row_data[column_name] = value

                csvwriter.writerow(row_data)
                existing_data.add(raw_tuple)




class AddEntryDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Add Entry")
        self.setFixedSize(420, 320)

        # Main layout
        layout = QVBoxLayout()
        form_layout = QFormLayout()

        # Set font style
        label_font = QFont("Segoe UI", 10)  # Clean modern font
        input_font = QFont("Segoe UI", 10)

        # Title Field
        self.title_input = QLineEdit()
        self.title_input.setFont(input_font)
        self.title_input.setStyleSheet("padding: 5px; border-radius: 5px; border: 1px solid #ccc;")

        # Username Field
        self.username_input = QLineEdit()
        self.username_input.setFont(input_font)
        self.username_input.setStyleSheet("padding: 5px; border-radius: 5px; border: 1px solid #ccc;")

        # Password Field
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setFont(input_font)
        self.password_input.setStyleSheet("padding: 5px; border-radius: 5px; border: 1px solid #ccc;")

        # Password Buttons (Show/Generate)
        self.toggle_password_button = QPushButton("👁 Show")
        self.toggle_password_button.setFixedWidth(70)
        self.toggle_password_button.setStyleSheet("background-color: #f0f0f0; border-radius: 5px; padding: 5px;")
        self.toggle_password_button.clicked.connect(self.toggle_password_visibility)

        self.generate_password_button = QPushButton("🔄 Generate")
        self.generate_password_button.setFixedWidth(90)
        self.generate_password_button.setStyleSheet("background-color: #4CAF50; color: white; border-radius: 5px; padding: 5px;")
        self.generate_password_button.clicked.connect(self.generate_password)

        # Password Row Layout
        password_layout = QHBoxLayout()
        password_layout.addWidget(self.password_input)
        password_layout.addWidget(self.toggle_password_button)
        password_layout.addWidget(self.generate_password_button)

        # Notes Field
        self.notes_input = QTextEdit()
        self.notes_input.setFont(input_font)
        self.notes_input.setStyleSheet("padding: 5px; border-radius: 5px; border: 1px solid #ccc;")

        # Add fields to form layout
        form_layout.addRow(QLabel("Title:"), self.title_input)
        form_layout.addRow(QLabel("Username:"), self.username_input)
        form_layout.addRow(QLabel("Password:"), password_layout)
        form_layout.addRow(QLabel("Notes:"), self.notes_input)

        # Apply font to labels
        for i in range(form_layout.rowCount()):
            form_layout.itemAt(i, QFormLayout.ItemRole.LabelRole).widget().setFont(label_font)

        # Buttons (OK & Cancel)
        self.ok_button = QPushButton("✔ OK")
        self.ok_button.setStyleSheet("background-color: #008CBA; color: white; border-radius: 5px; padding: 8px; font-size: 12px;")

        self.cancel_button = QPushButton("✖ Cancel")
        self.cancel_button.setStyleSheet("background-color: #f44336; color: white; border-radius: 5px; padding: 8px; font-size: 12px;")

        # Button Layout
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)

        layout.addLayout(form_layout)
        layout.addLayout(button_layout)

        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        self.setLayout(layout)

    def toggle_password_visibility(self):
        """Toggle password visibility between hidden and shown."""
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_password_button.setText("🙈 Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_password_button.setText("👁 Show")

    def generate_password(self):
        """Generate a secure password and insert it into the input field."""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        self.password_input.setText(''.join(secrets.choice(alphabet) for _ in range(12)))
        
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = FrontPage()
    window.show()
    sys.exit(app.exec())
