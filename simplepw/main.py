import sqlite3
import click
import string
import secrets
import bcrypt
from cryptography.fernet import Fernet
from pathlib import Path
import os


def get_config_dir():
  """
  Determines the appropriate configuration directory path based on the operating system.

  Returns:
    A pathlib.Path object representing the configuration directory path.
  """
  if os.name == 'nt':
    return Path(os.environ['APPDATA']) / CONFIG_DIR_NAME
  else:
    return Path.home() / f".{CONFIG_DIR_NAME}"
  
# Define application constants
CONFIG_DIR_NAME = 'spw'
DATABASE_NAME = 'password_store.db'
CONFIG_KEY_FILE = 'pw.key'
MASTER_PASSWORD_FILE = Path(get_config_dir()) / 'master_password.hash'  # Use Path object


def ensure_setup():
    """Creates necessary directories, files, and database setups for the application."""
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    create_encryption_key(config_dir)
    create_password_database(config_dir)
    click.echo(f"Password manager setup complete. Data directory: {config_dir}")

def get_database_connection():
    """Return a connection to the database, ensuring it references the correct path."""
    db_path = get_config_dir() / DATABASE_NAME
    return sqlite3.connect(db_path)


def create_encryption_key(config_dir):
    """Creates an encryption key if it does not exist."""
    key_file = config_dir / CONFIG_KEY_FILE
    if not key_file.exists():
        try:
            with open(key_file, 'wb') as file:
                file.write(Fernet.generate_key())
        except IOError as e:
            print(f"Failed to create key file: {e}")

def create_password_database(config_dir):
    """Creates the passwords table in the database if it does not exist."""
    database_path = config_dir / DATABASE_NAME
    try:
        conn = sqlite3.connect(database_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                encrypted_password TEXT NOT NULL
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Failed to create or connect to database: {e}")
    finally:
        conn.close()


def create_database(database_path):
  """Creates a new database with a 'passwords' table at the specified path.

  Args:
    database_path: The path to the database file.
  """
  conn = sqlite3.connect(database_path)  # Connect to the database
  c = conn.cursor()

  # Define default table name and schema
  table_name = "passwords"
  table_schema = {
      "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
      "name": "TEXT NOT NULL",
      "encrypted_password": "TEXT NOT NULL"  # Updated column name for clarity
  }

  # Build CREATE TABLE statement dynamically
  columns = ", ".join([f"{col} {schema}" for col, schema in table_schema.items()])
  sql = f"""CREATE TABLE IF NOT EXISTS {table_name} ({columns})"""

  try:
    c.execute(sql)
    print(f"Database '{database_path}' created successfully.")
  except sqlite3.Error as e:
    print("Error creating table:", e)

  conn.commit()  # Save changes
  conn.close()

def load_key():
    """Loads the encryption key from the key file in the configuration directory."""
    key_file_path = get_config_dir() / CONFIG_KEY_FILE
    try:
        with open(key_file_path, 'rb') as file:
            return file.read()
    except IOError as e:
        print(f"Failed to read key file: {e}")
        return None


def encrypt_message(message, key):
    """Encrypt a message using the provided key."""
    try:
        f = Fernet(key)
        return f.encrypt(message.encode())
    except Exception as e:
        print(f"Failed to encrypt message: {e}")
        return None

def decrypt_message(encrypted_message, key):
    """Decrypt a message using the provided key."""
    try:
        f = Fernet(key)
        return f.decrypt(encrypted_message).decode()
    except Exception as e:
        print(f"Failed to decrypt message: {e}")
        return None


def get_next_id():
    conn = sqlite3.connect('password_store.db')
    c = conn.cursor()
    c.execute('SELECT MAX(id) FROM passwords')
    data = c.fetchone()
    conn.close()

    if data[0] is None:
        return 1  # No entries yet, start with ID 1
    else:
        return data[0] + 1  # Return the highest ID + 1



def generate_password(length):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(length))


def set_master_password():
    """Sets the master password with proper error checking."""
    password = click.prompt('Enter a new master password:', hide_input=True)
    password_confirm = click.prompt('Confirm your new master password:', hide_input=True)
    if password != password_confirm:
        click.echo("Passwords do not match. Please try again.")
        return False

    try:
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        with open(get_config_dir() / 'master_password.hash', 'wb') as file:
            file.write(hashed_password)
        click.echo("Master password set successfully.")
        return True
    except IOError as e:
        click.echo(f"Failed to write master password: {e}")
        return False


def verify_master_password():
    """Verifies the master password entered by the user."""
    try:
        with open(get_config_dir() / 'master_password.hash', 'rb') as file:
            stored_hash = file.read()
    except FileNotFoundError:
        click.echo("Master password not found. Please set a master password first.")
        return False

    password = click.prompt('Enter your master password:', hide_input=True)
    if bcrypt.checkpw(password.encode(), stored_hash):
        click.echo("Password verified successfully.")
        return True
    else:
        click.echo("Incorrect password. Please try again.")
        return False

def save_password(name, password):
    """Saves the named password into the database after encryption."""
    ensure_setup()  # Ensure setup is complete which in turn ensures database is configured
    key = load_key()
    if key is None:
        click.echo("Encryption key is missing. Cannot secure the password.")
        return

    encrypted_password = encrypt_message(password, key)
    if encrypted_password is None:
        click.echo("Failed to encrypt the password.")
        return

    try:
        conn = get_database_connection()
        c = conn.cursor()
        c.execute("INSERT INTO passwords (name, encrypted_password) VALUES (?, ?)", (name, encrypted_password.hex()))
        conn.commit()
    except sqlite3.Error as e:
        click.echo(f"Failed to save password: {e}")
    finally:
        conn.close()
        click.echo(f"Password '{name}' added successfully.")


def delete_password(entry_id):
    """Deletes a password entry based on its ID from the database."""
    conn = get_database_connection()
    c = conn.cursor()
    try:
        # Check if the entry exists
        c.execute("SELECT id FROM passwords WHERE id = ?", (entry_id,))
        if c.fetchone() is None:
            click.echo("No password found with the provided ID.")
            return
    
        # If the entry exists, proceed with deletion
        c.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
        conn.commit()
        click.echo("Password deleted successfully.")
    except sqlite3.Error as e:
        click.echo(f"Failed to delete password: {e}")
    finally:
        conn.close()


def delete_all_passwords():
    """Deletes all password entries from the database after confirmation."""
    # Confirm the user wants to delete all passwords
    confirmation = click.confirm("Are you sure you want to delete ALL saved passwords? This action cannot be undone.", default=False)
    if confirmation:
        try:
            conn = get_database_connection()
            c = conn.cursor()
            c.execute("DELETE FROM passwords")
            conn.commit()
            click.echo("All passwords have been successfully deleted.")
        except sqlite3.Error as e:
            click.echo(f"Database error: {e}")
        finally:
            conn.close()
    else:
        click.echo("Deletion cancelled.")


def display_saved_passwords():
    """Displays all saved passwords within the database with decrypted forms."""
    key = load_key()
    if not key:
        click.echo("Failed to load the encryption key.")
        return

    try:
        conn = get_database_connection()
        c = conn.cursor()
        c.execute('SELECT id, name, encrypted_password FROM passwords')
        passwords = c.fetchall()
    except sqlite3.Error as e:
        click.echo(f"Database error when trying to retrieve passwords: {e}")
        return
    finally:
        if conn:
            conn.close()

    if not passwords:
        click.echo("No saved passwords found.")
        return

    # Display header
    click.echo("{:<5} | {:<20} | {:<30}".format("ID", "Name", "Password"))
    click.echo("-" * 60)

    # Loop through each password record
    for entry_id, name, encrypted_pass in passwords:
        decrypted_pass = decrypt_message(bytes.fromhex(encrypted_pass), key)
        if decrypted_pass is None:
            decrypted_pass = "Error decrypting password"
        click.echo("{:<5} | {:<20} | {:<30}".format(entry_id, name, decrypted_pass))


def add_existing_password():
    """Prompts the user for an existing password's name and password, then saves it to the password store using the save_password function."""
    name = click.prompt('Please enter the name for the password', type=str)
    password = click.prompt('Please enter the password', hide_input=True, type=str)

    save_password(name, password)

def main_menu():
    click.clear()
    while True:
        click.echo("\nMain Menu:")
        click.echo("1. Add Password")
        click.echo("2. Manage Saved Passwords")
        click.echo("3. Exit")
        choice = click.prompt("Please enter your choice", type=int)

        if choice == 1:
            add_password_menu()
        elif choice == 2:
            manage_passwords_menu()
        elif choice == 3:
            click.echo("Exiting.")
            break
        else:
            click.echo("Invalid selection. Please try again.")

def add_password_menu():
    while True:
        click.echo("\nAdd Password Menu:")
        click.echo("1. Generate and Save a New Password")
        click.echo("2. Add an Existing Password")
        click.echo("3. Back to Main Menu")
        choice = click.prompt("Please enter your choice", type=int)

        if choice == 1:
            length = click.prompt('Enter the desired password length', default=24, type=int)
            name = click.prompt('Enter a name for this password', type=str)
            password = generate_password(length)
            save_password(name, password)
            click.echo(f"Generated and saved password: {password}")
        elif choice == 2:
            add_existing_password()
        elif choice == 3:
            click.clear()
            return
        else:
            click.echo("Invalid selection. Please try again.")


def manage_passwords_menu():
    display_saved_passwords()
    while True:
        click.echo("\nManage Saved Passwords Menu:")
        click.echo("1. Delete a Specific Password")
        click.echo("2. Delete All Passwords")
        click.echo("3. Back to Main Menu")
        choice = click.prompt("Please enter your choice", type=int)
        if choice == 1:
            entry_id = click.prompt('Enter the ID of the password to delete', type=int)
            delete_password(entry_id)
        elif choice == 2:
            delete_all_passwords()
        elif choice == 3:
            click.clear()
            return
        else:
            click.echo("Invalid selection. Please try again.")


@click.command()
@click.option('--length', default=24, help='Password length', required=False)
def main(length):
    click.echo("Welcome to Password Manager")
    ensure_setup()

    if not MASTER_PASSWORD_FILE.exists() or not verify_master_password():
        click.echo("Setting or verifying master password...")
        if not set_master_password() and not verify_master_password():
            click.echo("Failed to set or verify master password. Exiting.")
            return

    main_menu()

if __name__ == '__main__':
    main()
