import pyshark 
import tkinter as tk 
from tkinter import ttk, messagebox, filedialog
import datetime


class PacketCaptureApp:
    def __init_self(self, root):
        self.root = root
        self.root.title("Packet Capture App")
        self.root.geometry("700x600")
        self.create_widgets()
        self.capture = None

    def create_widgets(self):
        self.start_button = ttk.Button(self.root, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)

        self.stop_button = ttk.Button(self.root, text="Stop Capture", command=self.stop_capture)
        self.stop_button.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)

        self.save_button = ttk.Button(self.root, text="Save Capture", command=self.save_capture)
        self.save_button.grid(row=0, column=2, padx=10, pady=10, sticky=tk.W)

        self.text = tk.Text(self.root, wrap=tk.WORD, width=70, height=20)
        self.text.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

    def start_capture(self):
        self.capture = pyshark.LiveCapture(interface='wlan0')
        self.capture.set_debug()
        self.capture.sniff()
        
