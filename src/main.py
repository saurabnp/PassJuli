from login import FrontPage
from PyQt6 import QtWidgets
import sys

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = FrontPage()
    window.show()
    sys.exit(app.exec())
