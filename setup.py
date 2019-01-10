from setuptools import setup, find_packages
setup(
    name="ImplGPG",
    version="1.0",
    packages=find_packages(),
    install_requires=['flask', 'gunicorn', 'psycopg2-binary', 'flask_sqlalchemy', 'flask_migrate', 'flask_login', 'flask_gnupg', 'flask_bootstrap', 'flask_wtf', 'boto3', 'arrow', 'flask_principal'],
    author="Michał Doliński",
    author_email="michal.dolinski@student.wat.edu.pl",
    description="Model uwierzytelniania wykorzystujący zaufaną trzecią stronę (mechanizm GPG) zaimplementowany do usługi przechowywania plików na serwerze.",

)