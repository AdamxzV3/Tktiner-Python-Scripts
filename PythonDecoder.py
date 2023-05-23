import tkinter as tk
from tkinter import ttk
import base64
import codecs
import urllib.parse
import binascii
import re
import quopri
import html
import base58

def base64_decoder(input_str):
    try:
        decoded_bytes = base64.b64decode(input_str)
        return decoded_bytes.decode('utf-8')
    except:
        return "Invalid Base64 input."

def ascii_decoder_octal(input_str):
    try:
        octal_values = input_str.split('\\')[1:]
        decoded_str = ''.join(chr(int(octal, 8)) for octal in octal_values if octal)
        return decoded_str
    except:
        return "Invalid ASCII (Octal) input."

def ascii_decoder_hexadecimal(input_str):
    try:
        hex_values = input_str.split('\\')[1:]
        decoded_str = ''.join(chr(int(hex_value, 16)) for hex_value in hex_values if hex_value)
        return decoded_str
    except:
        return "Invalid ASCII (Hexadecimal) input."

def ascii_decoder_decimal(input_str):
    try:
        decoded_str = ''.join(chr(int(decimal)) for decimal in input_str.split(', '))
        return decoded_str
    except:
        return "Invalid ASCII (Decimal) input."

def url_decoder(input_str):
    try:
        decoded_str = urllib.parse.unquote(input_str)
        return decoded_str
    except:
        return "Invalid URL input."

def hex_decoder(input_str):
    try:
        decoded_str = codecs.decode(input_str, 'hex').decode('utf-8')
        return decoded_str
    except:
        return "Invalid Hex input."

def unicode_decoder(input_str):
    try:
        decoded_str = input_str.encode('utf-8').decode('unicode-escape')
        return decoded_str
    except:
        return "Invalid Unicode input."

def html_entity_decoder(input_str):
    try:
        decoded_str = codecs.decode(input_str, 'html-entities').encode('utf-8').decode('utf-8')
        return decoded_str
    except:
        return "Invalid HTML entity input."

def utf8_decoder(input_str):
    try:
        decoded_bytes = base64.b64decode(input_str)
        decoded_str = decoded_bytes.decode('utf-8')
        return decoded_str
    except:
        return "Invalid UTF-8 input."

def rot13_decoder(input_str):
    try:
        decoded_str = codecs.decode(input_str, 'rot_13')
        return decoded_str
    except:
        return "Invalid ROT13 input."

def binary_decoder(input_str):
    try:
        binary_values = input_str.split(' ')
        decoded_str = ''.join(chr(int(binary, 2)) for binary in binary_values if binary)
        return decoded_str
    except:
        return "Invalid binary input."

def base32_decoder(input_str):
    try:
        decoded_bytes = base64.b32decode(input_str, casefold=True)
        return decoded_bytes.decode('utf-8')
    except:
        return "Invalid Base32 input."

def quoted_printable_decoder(input_str):
    try:
        decoded_str = quopri.decodestring(input_str)
        return decoded_str.decode('utf-8')
    except:
        return "Invalid Quoted-Printable input."

def punycode_decoder(input_str):
    try:
        decoded_str = input_str.encode('ascii').decode('punycode')
        return decoded_str
    except:
        return "Invalid Punycode input."

def reverse_text_decoder(input_str):
    try:
        reversed_str = input_str[::-1]
        return reversed_str
    except:
        return "Invalid input."

def base58_decoder(input_str):
    try:
        decoded_data = base58.b58decode(input_str)
        return decoded_data.decode()
    except ValueError as e:
        return "Invalid Base58 input: " + str(e)

def base85_decoder(input_str):
    try:
        decoded_data = base64.a85decode(input_str)
        return decoded_data.decode()
    except ValueError as e:
        return "Invalid Base85 input: " + str(e)

class DecoderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Text Decoder")
        self.root.configure(bg="#333333")

        self.create_widgets()

    def create_widgets(self):
        self.choice_label = tk.Label(self.root, text="Choose an option:", font=("Arial", 14), bg="#333333", fg="#FFFFFF")
        self.choice_label.pack(pady=20)

        self.choice_var = tk.StringVar()
        self.choice_var.set("1")

        self.choices_frame = ttk.Notebook(self.root)
        self.choices_frame.pack()

        options = [
            ('Base64 Decoder', '1', 'Base'), ('Base32 Decoder', '2', 'Base'), ('Base85 Decoder / ASCII85', '3', 'Base'), ('Base58 Decoder', '4', 'Base'),
            ('ASCII Decoder (Octal)', '5', 'ASCII Decoding'), ('ASCII Decoder (Hexadecimal)', '6', 'ASCII Decoding'), ('ASCII Decoder (Decimal)', '7', 'ASCII Decoding'),
            ('URL Decoder', '8', 'URL Decoding'), ('Hex Decoder', '9', 'Hex Decoding'), ('Unicode Decoder', '10', 'Unicode Decoding'),
            ('HTML Entity Decoder', '11', 'HTML Entity Decoding'), ('UTF-8 Decoder', '12', 'UTF-8 Decoding'), ('ROT13 Decoder', '13', 'ROT13 Decoding'),
            ('Binary Decoder', '14', 'Binary Decoding'), ('Quoted-Printable Decoder', '15', 'Quoted-Printable Decoding'), ('Reverse Text Decoder', '16', 'Reverse Text Decoding')
        ]

        decoding_options = {}

        for option_text, option_value, tab_title in options:
            if tab_title not in decoding_options:
                decoding_options[tab_title] = []

            decoding_options[tab_title].append((option_text, option_value))

        for tab_title, tab_options in decoding_options.items():
            frame = ttk.Frame(self.choices_frame)
            self.choices_frame.add(frame, text=tab_title, padding=10)

            for option_text, option_value in tab_options:
                button_frame = tk.Frame(frame, bg="#333333")
                button_frame.pack(pady=5)

                button = tk.Radiobutton(
                    button_frame,
                    text=option_text,
                    variable=self.choice_var,
                    value=option_value,
                    font=("Arial", 12),
                    bg="#333333",
                    activebackground="#555555",
                    fg="#FFFFFF",
                    selectcolor="#333333"
                )
                button.pack(side="left", padx=10)

                button_panel = tk.Frame(button_frame, bg="#FF69B4", bd=1, relief="raised")
                button_panel.pack(side="left", padx=5)
                button_panel.bind("<Enter>", lambda event, panel=button_panel: panel.configure(bg="#FF1493"))
                button_panel.bind("<Leave>", lambda event, panel=button_panel: panel.configure(bg="#FF69B4"))

        self.choices_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.decode_button = tk.Button(self.root, text="Decode", command=self.decode, font=("Arial", 14), bg="#FF69B4", fg="#FFFFFF")
        self.decode_button.pack(pady=20)

        self.input_label = tk.Label(self.root, text="Enter the input to decode:", font=("Arial", 14), bg="#333333", fg="#FFFFFF")
        self.input_label.pack()

        self.input_text = tk.Text(self.root, height=5, width=50, font=("Arial", 12))
        self.input_text.pack()

        self.output_label = tk.Label(self.root, text="Decoded output:", font=("Arial", 14), bg="#333333", fg="#FFFFFF")
        self.output_label.pack()

        self.output_text = tk.Text(self.root, height=5, width=50, font=("Arial", 12))
        self.output_text.pack()


    def decode(self):
        choice = self.choice_var.get()
        input_str = self.input_text.get("1.0", tk.END).strip()

        if choice == '1':
            decoded_str = base64_decoder(input_str)
        elif choice == '2':
            decoded_str = ascii_decoder_octal(input_str)
        elif choice == '3':
            decoded_str = ascii_decoder_hexadecimal(input_str)
        elif choice == '4':
            decoded_str = ascii_decoder_decimal(input_str)
        elif choice == '5':
            decoded_str = url_decoder(input_str)
        elif choice == '6':
            decoded_str = hex_decoder(input_str)
        elif choice == '7':
            decoded_str = unicode_decoder(input_str)
        elif choice == '8':
            decoded_str = html_entity_decoder(input_str)
        elif choice == '9':
            decoded_str = utf8_decoder(input_str)
        elif choice == '10':
            decoded_str = rot13_decoder(input_str)
        elif choice == '11':
            decoded_str = binary_decoder(input_str)
        elif choice == '12':
            decoded_str = base58_decoder(input_str)
        elif choice == '13':
            decoded_str = base32_decoder(input_str)
        elif choice == '14':
            decoded_str = quoted_printable_decoder(input_str)
        elif choice == '15':
            decoded_str = reverse_text_decoder(input_str)
        elif choice == '16':
            decoded_str = base85_decoder(input_str)
        else:
            decoded_str = "Invalid choice."

        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, decoded_str)


if __name__ == "__main__":
    root = tk.Tk()
    app = DecoderApp(root)
    root.mainloop()