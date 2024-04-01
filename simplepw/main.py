import json
import click
import string
import secrets
import uuid
import bcrypt
from cryptography.fernet import Fernet
from pathlib import Path
import os

# Determine the appropriate configuration directory based on the operating system
config_dir_name = 'spw'
if os.name == 'nt':  # Windows
    CONFIG_DIR = Path(os.environ['APPDATA']) / config_dir_name
else:
    CONFIG_DIR = Path.home() / f".{config_dir_name}"

CONFIG_KEY_FILE = CONFIG_DIR / 'pw.key'
PASSWORD_STORE_FILE = CONFIG_DIR / 'data.json'
MASTER_PASSWORD_FILE = CONFIG_DIR / 'master_password.hash'


def ensure_setup():
    if not CONFIG_DIR.exists():
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if not CONFIG_KEY_FILE.exists():
        key = Fernet.generate_key()
        with open(CONFIG_KEY_FILE, 'wb') as key_file:
            key_file.write(key)


def load_key():
    return CONFIG_KEY_FILE.read_bytes()


def encrypt_message(message, key):
    return Fernet(key).encrypt(message.encode())


def decrypt_message(encrypted_message, key):
    return Fernet(key).decrypt(encrypted_message).decode()


def generate_password(length):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(length))


def set_master_password():
    click.echo("It looks like you're running the Password Manager for the first time.")
    show_tutorial()
    password = click.prompt('Please set a master password for accessing this tool', hide_input=True, confirmation_prompt=True, type=str)
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    with open(MASTER_PASSWORD_FILE, 'wb') as file:
        file.write(hashed)
    click.echo("Master password set successfully.")


def verify_master_password():
    try:
        stored_hash = MASTER_PASSWORD_FILE.read_bytes()
        password = click.prompt('Enter your master password to unlock the tool', hide_input=True, type=str)
        if bcrypt.checkpw(password.encode(), stored_hash):
            click.echo("Password verified successfully. Access granted.")
            return True
        else:
            click.echo("Incorrect password. Access denied.")
            return False
    except FileNotFoundError:
        click.echo("Master password not set. Setting up now.")
        set_master_password()
        return True


def save_password(name, password):
    key = load_key()
    encrypted_password = encrypt_message(password, key)
    entry_id = str(uuid.uuid4())
    try:
        with open(PASSWORD_STORE_FILE, 'r+') as file:
            data = json.load(file)
            data[entry_id] = {"name": name, "password": encrypted_password.hex()}
            file.seek(0)
            file.truncate()
            json.dump(data, file)
    except FileNotFoundError:
        with open(PASSWORD_STORE_FILE, 'w') as file:
            json.dump({entry_id: {"name": name, "password": encrypted_password.hex()}}, file)


def delete_password(entry_id):
    key = load_key()
    try:
        data = json.loads(PASSWORD_STORE_FILE.read_text())
        if entry_id in data:
            entry = data[entry_id]
            decrypted_pass = decrypt_message(bytes.fromhex(entry["password"]), key)
            confirmation = click.confirm(f"Are you sure you want to delete the password for '{entry['name']}'?",
                                         default=False)
            if confirmation:
                del data[entry_id]
                PASSWORD_STORE_FILE.write_text(json.dumps(data))
                click.echo("Password deleted successfully.")
            else:
                click.echo("Deletion cancelled.")
        else:
            click.echo("No matching ID found.")
    except FileNotFoundError:
        click.echo("No saved passwords found.")


def delete_all_passwords():
    confirmation = click.confirm("Are you sure you want to delete ALL saved passwords? This action cannot be undone.",
                                 default=False)
    if confirmation:
        try:
            PASSWORD_STORE_FILE.unlink()
            click.echo("All passwords have been successfully deleted.")
        except FileNotFoundError:
            click.echo("No saved passwords found.")
    else:
        click.echo("Deletion cancelled.")


def display_saved_passwords():
    key = load_key()
    try:
        data = json.loads(PASSWORD_STORE_FILE.read_text())
        if data:
            print(f"{'ID':<40} | {'Name':<20} | {'Password':<20}")
            print("-" * 80)
            for entry_id, details in data.items():
                decrypted_pass = decrypt_message(bytes.fromhex(details["password"]), key)
                print(f"{entry_id:<40} | {details['name']:<20} | {decrypted_pass:<20}")
        else:
            click.echo("No saved passwords found.")
    except FileNotFoundError:
        click.echo("No saved passwords found.")


def interactive_mode():
    click.clear()
    click.echo("Welcome to Password Manager")

    if not verify_master_password():
        click.echo("Master password verification failed. Exiting interactive mode.")
        return

    while True:
        click.echo("\n1. Generate and Save a Password")
        click.echo("2. Generate a Password without Saving")
        click.echo("3. List Saved Passwords")
        click.echo("4. Delete a Password")
        click.echo("5. Delete All Saved Passwords")
        click.echo("6. Exit")
        choice = click.prompt("\nPlease enter your choice", type=int)

        if choice == 1:
            length = click.prompt('\nPlease enter a password length', default=24, type=int)
            name = click.prompt('Please enter a name for the password', type=str)
            password = generate_password(length)
            save_password(name, password)
            click.echo(f'Generated and saved password: {password}\n')
        elif choice == 2:
            length = click.prompt('\nPlease enter a password length', default=24, type=int)
            password = generate_password(length)
            click.echo(f'Generated password: {password}\n')
        elif choice == 3:
            display_saved_passwords()
        elif choice == 4:
            entry_id = click.prompt('\nPlease enter the ID of the password to delete', type=str)
            delete_password(entry_id)
        elif choice == 5:
            delete_all_passwords()
        elif choice == 6:
            click.echo("\nExiting interactive mode. Goodbye!")
            break
        else:
            click.echo("\nInvalid choice. Please try again.")

        click.pause(info='\nPress any key to continue...')


def show_tutorial():
    tutorial_text = """
Welcome to the Password Manager Tutorial!

Important Notice: This password generator and password safe are provided "as is" without warranty of any kind. 
While designed with security in mind, the developer cannot guarantee its effectiveness for real-world use. 
It is strongly recommended to exercise caution and consider the potential risks before using this tool for sensitive information.

Enjoy using Password Manager!
"""
    click.echo(tutorial_text)


@click.command()
@click.option('--length', default=24, help='Password length')
@click.option('--save', is_flag=True, help='Save the generated password')
@click.option('--list', is_flag=True, help='List all saved passwords')
@click.option('--delete', type=str, help='Delete a password by its ID')
@click.option('--generate', is_flag=True, help='Generate a password without saving')
def main(length, save, list, delete, generate):
    ensure_setup()

    if generate and not (save or list or delete):
        password = generate_password(length)
        click.echo(f'Generated password: {password}')
        return

    if save or list or delete:
        if not verify_master_password():
            return

    if list:
        display_saved_passwords()
    elif delete:
        delete_password(delete)
    elif save:
        password = generate_password(length)
        click.echo(f'Generated password: {password}')
        name = click.prompt('Please enter a name for the password', type=str)
        save_password(name, password)
        click.echo("Password saved successfully.")
    else:
        interactive_mode()


if __name__ == '__main__':
    main()