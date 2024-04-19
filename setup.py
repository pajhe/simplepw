from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name='simplepw',
    version='0.2.3',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'cryptography>=2.8',
        'click',
        'bcrypt',
        'pathlib',
        'sqlite3'
    ],
    entry_points={
        "console_scripts": [
            "spw=simplepw.main:main",
        ],
    },
    author='pajhe',
    author_email= 'piejeys@proton.me',
    description='A CLI Application for generating and managing passwords',
    long_description= long_description,
    long_description_content_type="text/markdown",
    keywords='password generation',
)