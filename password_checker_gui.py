import tkinter as tk
from tkinter import StringVar, IntVar
import random
import string
import hashlib
import requests
import re

# Function to check password strength
def check_password_strength(password):
    if len(password) < 8:
        return "Weak: Password must be at least 8 characters long."
    if not re.search("[a-z]", password):
        return "Weak: Password must contain at least one lowercase letter."
    if not re.search("[A-Z]", password):
        return "Weak: Password must contain at least one uppercase letter."
    if not re.search("[0-9]", password):
        return "Weak: Password must contain at least one number."
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return "Weak: Password must contain at least one special character."
    return "Strong: Your password meets all the criteria."

# Function to check password breach
def check_password_breach(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    response = requests.get(url)

    if response.status_code == 200:
        if suffix in response.text:
            return "This password has been exposed in a breach. Please choose another one."
        else:
            return "This password has not been exposed in any known breach."
    else:
        return "Error checking password."

# Function to generate random password
def generate_password(length=12, include_special=True):
    characters = string.ascii_letters + string.digits
    if include_special:
        characters += "!@#$%^&*()"
    return ''.join(random.choice(characters) for _ in range(length))

# Update feedback with strength and breach check
def update_feedback(*args):
    password = password_var.get()
    strength_result = check_password_strength(password)
    breach_result = check_password_breach(password)
    feedback.set(f"{strength_result}\n{breach_result}")

# Generate and display random password
def display_generated_password():
    length = password_length.get()
    include_special = include_special_var.get()
    generated_password = generate_password(length=length, include_special=include_special)
    password_var.set(generated_password)
    feedback.set("Generated password. Check its strength and breach status!")

# Toggle password visibility
def toggle_password_visibility():
    if password_entry.cget("show") == "*":
        password_entry.config(show="")  # Show password
        toggle_button.config(text="Hide")
    else:
        password_entry.config(show="*")  # Hide password
        toggle_button.config(text="Show")

# GUI Setup
root = tk.Tk()
root.title("Password Checker with Generator")

# Variables
password_var = StringVar()
password_var.trace("w", update_feedback)

feedback = StringVar()
feedback.set("Type a password to see feedback.")

password_length = IntVar(value=12)  # Default password length
include_special_var = IntVar(value=1)  # Include special characters by default

# GUI Elements
tk.Label(root, text="Enter your password:").pack()

password_frame = tk.Frame(root)
password_frame.pack()

password_entry = tk.Entry(password_frame, textvariable=password_var, show="*")
password_entry.pack(side="left")

toggle_button = tk.Button(password_frame, text="Show", command=toggle_password_visibility)
toggle_button.pack(side="left")

tk.Label(root, textvariable=feedback, wraplength=300, justify="left").pack()

# Password Generator Options
tk.Label(root, text="Password Length:").pack()
tk.Spinbox(root, from_=8, to=32, textvariable=password_length).pack()
tk.Checkbutton(root, text="Include Special Characters", variable=include_special_var).pack()
tk.Button(root, text="Generate Password", command=display_generated_password).pack()

# Run the GUI
root.mainloop()
