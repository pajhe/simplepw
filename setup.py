from setuptools import setup, find_packages

setup(
    name='pwd0',  # Der Name Ihres Projekts
    version='0.1.7',  # Starten Sie mit der Version 1.0.0 oder einer anderen gewünschten Versionsnummer
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'click>=7.0',  # Ersetzen Sie dies entsprechend Ihrer tatsächlichen click-Version
        'cryptography>=2.8',  # Ersetzen Sie dies entsprechend Ihrer tatsächlichen cryptography-Version
        'click',  # Ersetzen Sie dies entsprechend Ihrer tatsächlichen click-Version
        'bcrypt'
    ],
    entry_points={
        'console_scripts': [
            'pwd0=pwd0.main:main',  # Definiert den Befehl 'pwdtool', der die Funktion 'main()' in 'main.py' aufruft
        ],
    },
    # Metadaten für Ihr Projekt
    author='PH',
    author_email='ph@example.com',
    description='Ein CLI-Tool zur lokalen Verwaltung von Passwörtern',
    keywords='Passwortverwaltung CLI',
    url='URL_zu_Ihrem_Projekt_Repository',  # Optional, falls das Projekt öffentlich verfügbar ist
)