from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, QTextEdit, QPushButton,QHBoxLayout, QLabel, QTableWidgetItem, QMessageBox,QMenu,QMainWindow,QApplication,QHeaderView
)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from addEntryDialog import AddEntryDialog
from PyQt6 import QtWidgets, uic,QtCore
from PyQt6.QtGui import QClipboard, QAction,QFont
from appdata import get_appdata_path,resource_path
import os,csv
from encrypt import encrypt,decrypt

class PasswordPage(QMainWindow):
    masterPassword=None
    def __init__(self,masterPassword):
        super().__init__()
        PasswordPage.masterPassword=masterPassword

        uic.loadUi(resource_path("../ui/password.ui"), self)
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
                                decrypted_password = decrypt(PasswordPage.masterPassword, col_data)  # Decrypt password
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

            # Create non-editable items
                site_item = QTableWidgetItem(site)
                username_item = QTableWidgetItem(username)
                password_item = QTableWidgetItem("********")
                notes_item = QTableWidgetItem(notes)

            # Set items to non-editable
                for item in [site_item, username_item, password_item, notes_item]:
                    item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)

                self.passwordTable.setItem(row_position, 0, site_item)
                self.passwordTable.setItem(row_position, 1, username_item)
                self.passwordTable.setItem(row_position, 2, password_item)
                self.passwordTable.setItem(row_position, 3, notes_item)

                self.save_to_csv(os.path.join(get_appdata_path(), "details.csv"))

    def save_to_csv(self, file_path):
        """Save only new unique data to CSV by comparing plaintext, and encrypting passwords before saving."""
        fieldnames = [self.passwordTable.horizontalHeaderItem(i).text() for i in range(self.passwordTable.columnCount())]
        master_password = PasswordPage.masterPassword

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
                        value = encrypt(PasswordPage.masterPassword, self.actual_passwords.get(row, ""))

                    row_data[column_name] = value

                csvwriter.writerow(row_data)
                existing_data.add(raw_tuple)


