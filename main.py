import tkinter as tk
from mac_finder.gui.main_window import MACFinderApp

def main():
    """Main entry point."""
    root = tk.Tk()
    app = MACFinderApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()