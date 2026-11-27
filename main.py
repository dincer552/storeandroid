import tkinter as tk
from mac_finder.gui.main_window import MACFinderApp


def main():
    root = tk.Tk()
    app = MACFinderApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
