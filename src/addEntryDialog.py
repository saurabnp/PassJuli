
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, QTextEdit, QPushButton,QHBoxLayout, QLabel, QTableWidgetItem, QMessageBox,QMenu,QMainWindow,QApplication,QHeaderView
)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from PyQt6 import QtWidgets, uic,QtCore
from PyQt6.QtGui import QClipboard, QAction,QFont
import string,secrets


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
        