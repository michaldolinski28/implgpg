import os
from flask import Flask, flash, request, redirect, url_for
import sys
import logging
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_gnupg import GnuPG
from flask_bootstrap import Bootstrap
from filters import datetimeformat, file_type
from flask_principal import Principal, Permission, RoleNeed

# Definicja aplikacji
app = Flask(__name__)
# Definicja konfiguracji
app.config.from_object(Config)
# Definicja bazy danych
db = SQLAlchemy(app)
migrate = Migrate(app, db)
# Definicja pakietu logowania
login = LoginManager(app)
login.login_view = 'login'
# Definicja pakietu uprawnień
principal = Principal(app)
# Definicja uprawnień administratora
admin_permission = Permission(RoleNeed('admin'))
# Definicja pakietu GPG
gpg = GnuPG(app)
# Komunikat wyświetlany, gdy niezalogowany użytkownik chce wejść na stronę bez dostępu dla niezalogowanych
login.login_message = u"Zaloguj się, by przejść dalej."
bootstrap = Bootstrap(app)
# Format błędów wyświetlanych w konsoli
logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level=logging.ERROR)
# Definicja formatu daty, czasu i rozszerzeń w liście plików
app.jinja_env.filters['datetimeformat'] = datetimeformat
app.jinja_env.filters['file_type'] = file_type

from app import routes, models