import tkinter as tk
from tkinter import StringVar
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

# Function to update feedback in GUI
def update_feedback(*args):
    password = password_var.get()
    strength_result = check_password_strength(password)
    breach_result = check_password_breach(password)
    feedback.set(f"{strength_result}\n{breach_result}")

# GUI Setup
root = tk.Tk()
root.title("Password Checker")

password_var = StringVar()
password_var.trace("w", update_feedback)

feedback = StringVar()
feedback.set("Type a password to see feedback.")

tk.Label(root, text="Enter your password:").pack()
tk.Entry(root, textvariable=password_var, show="*").pack()
tk.Label(root, textvariable=feedback, wraplength=300, justify="left").pack()

root.mainloop()
