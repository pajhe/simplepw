from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name='simplepw',  # Der Name Ihres Projekts
    version='0.2.2',  # Starten Sie mit der Version 1.0.0 oder einer anderen gewünschten Versionsnummer
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'cryptography>=2.8',  # Ersetzen Sie dies entsprechend Ihrer tatsächlichen cryptography-Version
        'click',  # Ersetzen Sie dies entsprechend Ihrer tatsächlichen click-Version
        'bcrypt',
        'pathlib'
    ],
    entry_points={
        "console_scripts": [
            "spw=simplepw.main:main",  # Replace 'your_package' with the actual package name
            # The module and function within your package that contains the main logic of your CLI tool.
        ],
    },
    # Metadaten für Ihr Projekt
    author='pajhe',
    author_email= 'piejeys@proton.me',
    description='A CLI Application for generating and managing passwords',
    long_description= long_description,
    long_description_content_type="text/markdown",
    keywords='password generation',
)