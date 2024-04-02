import json
import click
import string
import secrets
import uuid
import bcrypt
from cryptography.fernet import Fernet
from methods import ensure_setup, load_key, generate_password, save_password, delete_password, delete_all_passwords, display_saved_passwords, verify_master_password, add_existing_password
from pathlib import Path
import os

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
        click.echo("6. Add Existing Password")  # New option added
        click.echo("7. Exit")
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
        elif choice == 6:  # Handle adding existing password
            add_existing_password()
        elif choice == 7:
            click.echo("\nExiting interactive mode. Goodbye!")
            break
        else:
            click.echo("\nInvalid choice. Please try again.")

        click.pause(info='\nPress any key to continue...')


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