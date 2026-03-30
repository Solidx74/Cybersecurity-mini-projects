import re

def check_password(password):
    if len(password) < 8:
        return "Weak password: Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return "Weak password: Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Weak password: Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return "Weak password: Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Weak password: Password must contain at least one special character."
    return "Strong password!"

def password_checker():
    print("Welcome to the Password Strength Checker!")
    while True:
        password = input("Enter a password to check (or type 'exit' to quit): ")
        if password.lower() == 'exit':
            print("Thanks for using the Password Strength Checker. Goodbye!")
            break
        result = check_password(password)
        print(result)

if __name__ == "__main__":
    password_checker()