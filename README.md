# Password Checker with GUI and Random Password Generator
This project is a comprehensive Password Checker tool designed with both a command-line interface (CLI) and a Graphical User Interface (GUI). It includes features to evaluate password strength, check for breaches using the Have I Been Pwned API, generate secure passwords, and provide a user-friendly visual interface.

# Features
Password Strength Checker
Analyzes a password's strength based on:
Minimum length requirement (8+ characters).
Inclusion of:
Lowercase letters.
Uppercase letters.
Numbers.
Special characters.
Provides feedback such as Weak, Medium, or Strong.
Breach Detection
Uses the Have I Been Pwned API to check if a password has been exposed in a data breach.
Displays appropriate warnings if a password has been compromised.
Random Password Generator
Allows users to generate secure passwords with customizable options:
Length (8–32 characters).
Inclusion of special characters.
Automatically checks the strength of generated passwords.
Graphical User Interface (GUI)
Built using Tkinter, the GUI includes:
Password input field with a "Show/Hide Password" toggle.
Dynamic strength visualization using a progress bar.
Feedback on password strength and breach status.
Options for generating passwords with user-defined criteria.
Command-Line Interface (CLI)
Offers a text-based interaction for users who prefer terminal usage.
Saves breach check results to a breach_results.txt file for record-keeping.

# GUI Usage
Enter a password in the input field to check its strength and breach status.
Use the "Show/Hide Password" button to toggle visibility.
Adjust password length and special character inclusion for the generator.
Click "Generate Password" to create a secure password.
Review feedback on strength and breach status dynamically.

# Key Highlights
Real-Time Feedback: The GUI dynamically updates password strength and breach status as you type.
Visual Strength Indicator: A progress bar displays password strength (Weak, Medium, Strong).
Security Features: Integrates the Have I Been Pwned API for real-world breach detection.
User-Friendly Design: GUI features intuitive controls for password entry, generation, and customization.

# Credits
Developed by: es2323
Feel free to contribute or raise issues in the repository. 😊

Let me know if you need help with further customization or details! 🚀
