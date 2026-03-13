import sys
import os

# Fix paths for Windows and Linux
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from ui.main_app import IOCHunterApp

if __name__ == "__main__":
    app = IOCHunterApp()
    app.mainloop()
