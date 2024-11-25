import hashlib
import requests
import re

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

def main():
    while True:
        password = input("Enter your password (or type 'exit' to quit): ")
        if password.lower() == "exit":
            print("Goodbye!")
            break
        print(check_password_strength(password))
        print(check_password_breach(password))


# Run the main function
if __name__ == "__main__":
    main()
