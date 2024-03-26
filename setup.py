from setuptools import setup, find_packages

setup(
    name='simple-pw',  # Der Name Ihres Projekts
    version='0.1.8',  # Starten Sie mit der Version 1.0.0 oder einer anderen gewünschten Versionsnummer
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'cryptography>=2.8',  # Ersetzen Sie dies entsprechend Ihrer tatsächlichen cryptography-Version
        'click',  # Ersetzen Sie dies entsprechend Ihrer tatsächlichen click-Version
        'bcrypt'
    ],
    entry_points={
        'console_scripts': [
            'spw=spw.main:main',  # Definiert den Befehl 'pwdtool', der die Funktion 'main()' in 'main.py' aufruft
        ],
    },
    # Metadaten für Ihr Projekt
    author='piejeys',
    description='A CLI Application for generating and save passwords',
    keywords='password generation',
)