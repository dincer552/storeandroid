import tkinter as tk
from .main_window import MACFinderApp


def main():
    """Main entry point for MAC Finder."""
    root = tk.Tk()
    app = MACFinderApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()