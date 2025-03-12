import tkinter as tk
from gui import PasswordManagerApp

def main():
    """Main entry point of the application"""
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()