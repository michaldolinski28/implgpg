import os, json, boto3, botocore, io
from flask import render_template, flash, redirect, url_for, request, Flask, send_from_directory, Markup, after_this_request, Response, session
from flask_login import current_user, login_user, logout_user, login_required
from app import app, db, gpg, admin_permission
from app.forms import LoginForm, RegistrationForm
from app.models import User
from werkzeug.urls import url_parse 
from werkzeug import secure_filename
from werkzeug.datastructures import FileStorage
from flask_principal import identity_loaded, RoleNeed, UserNeed, Identity, AnonymousIdentity, identity_changed

def _get_s3_resource():
    return boto3.resource('s3')

# Definicja używanego bucketu    
def get_bucket():
    s3_resource = _get_s3_resource()
    return s3_resource.Bucket(app.config["S3_BUCKET"])

# Sprawdzenie rozszerzenia dodawanego pliku
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

# Sprawdzenie rozszerzenia dodawanego klucza          
def allowed_key(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config["KEY_EXTENSION"]
 
# Strona główna
@app.route('/')
@app.route('/index')
def index():
    # Jeśli użytkownik jest zalogowany - przejdź na stronę profilu
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    return render_template('index.html', title='Strona główna')

# Strona profilu
@app.route('/profile')    
@login_required
def profile():
    return render_template('profile.html', title='Twój profil', admin=admin_permission)
    
# Strona logowania
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Jeśli użytkownik jest zalogowany - przejdź na stronę główną
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    # Deklaracja formularzu logowania
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        decrypted_data = gpg.decrypt(form.crypted.data, passphrase=form.password.data)
        status = str(decrypted_data.status)
        stderr = str(decrypted_data.stderr)
        decrypted_string = str(decrypted_data.data)
        # Jeśli zaszyfrowano złym kluczem lub klucza nie ma w bazie - wyświetl komunikat
        if (status == "decryption failed") or ("\"" + form.username.data + " " not in stderr):
            flash('Nie zaimportowano klucza lub tekst zaszyfrowano kluczem innego użytkownika!')
            return redirect(url_for('login'))
        # Jeśli podano niepoprawny login, hasło albo zaszyfrowano zły tekst - wyświetl komunikat
        if (decrypted_string != "b'Implementacja modelu uwierzytelnienia'") or (user is None or not user.check_password(form.password.data)):
            flash('Nieprawidłowy login, hasło lub źle zaszyfrowany tekst!')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        # Zmiana uprawnień użytkownika z niezalogowanego na zalogowanego
        identity_changed.send(app, identity=Identity(user.id))
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Logowanie', form=form)

# Wylogowywanie    
@app.route('/logout')
def logout():
    logout_user()
    # Zmiana uprawnień użytkownika z zalogowanego na niezalogowanego
    identity_changed.send(app, identity=AnonymousIdentity())
    flash('Pomyślnie wylogowano!')
    return redirect(url_for('index'))

# Strona rejestracji    
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Jeśli użytkownik jest zalogowany - przejdź na stronę główną
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    # Deklaracja formularzu rejestracji
    form = RegistrationForm()
    if form.validate_on_submit():
        # Generacja klucza na podstawie danych z formularza
        input_data = gpg.gen_key_input(key_type="RSA", key_length=1024, name_real= form.username.data, name_email= "\'" + form.email.data + "\'", passphrase= form.password.data)
        key = gpg.gen_key(input_data)
        # Eksport klucza do pliku
        ascii_armored_public_keys = gpg.export_keys(key.fingerprint)
        ascii_armored_private_keys = gpg.export_keys(key.fingerprint, True, passphrase=form.password.data)
        with open("app/keys/" + form.username.data + "_keys.asc", 'w') as f:
            f.write(ascii_armored_public_keys)
            f.write(ascii_armored_private_keys)
        # Tworzenie wpisu użytkownika w bazie danych
        user = User(username=form.username.data, email=form.email.data, public_key=ascii_armored_public_keys, private_key=ascii_armored_private_keys)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        session['username'] = form.username.data
        flash(Markup('Rejestracja zakończona sukcesem, pobierz klucze potrzebne do zalogowania <a href=/keys>tutaj</a>!'))
    return render_template('register.html', title='Rejestracja', form=form)

# Pobieranie kluczy ze strony profilu
@app.route("/downloadkeys", methods=['POST'])
def downloadkeys(): 
    # Eksport klucza do pliku
    with open("app/keys/" + current_user.username + "_keys.asc", 'w') as f:
        f.write(current_user.public_key)
        f.write(current_user.private_key)
    return send_from_directory(directory="keys", filename=current_user.username + "_keys.asc", as_attachment=True)
    
# Pobieranie kluczy ze strony rejestracji
@app.route('/keys', methods=['GET', 'POST'])
def keys():
    # Pobieranie zmiennej (nazwa użytkownika) z formularza rejestracji
    name = session.get('username')
    return send_from_directory(directory="keys", filename = name + "_keys.asc", as_attachment=True)

# Strona instrukcji
@app.route('/manual')
def manual():
    return render_template('manual.html', title='Instrukcja logowania')

# Strona plików           
@app.route('/files')
@login_required
def files():
    # Listowanie plików
    my_bucket = get_bucket()
    summaries = my_bucket.objects.all()

    return render_template('files.html', my_bucket=my_bucket, files=summaries, title='Lista plików')

# Dodawanie plików    
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if request.method == 'POST':
        # Sprawdzenie, czy wybrano plik
        if 'file' not in request.files:
            flash("Nie wybrano żadnego pliku!")
            return redirect(url_for('files'))
        
        file = request.files['file']
        
        # Sprawdzenie, czy wybrano plik
        if file.filename == "":
            flash("Nie wybrano żadnego pliku!")
            return redirect(url_for('files'))
        
        # Sprawdzenie, czy użytkownik ma uprawnienia do dodawania        
        with admin_permission.require(http_exception=403):
            # Sprawdzenie czy plik ma dopuszczalny format
            if file and allowed_file(file.filename): 
                my_bucket = get_bucket()
                my_bucket.Object(file.filename).put(Body=file)
                flash('Pomyślnie dodano plik!')
                return redirect(url_for('files'))
            
        # Definicja akcji, gdy nie wybrano pliku albo plik ma niedopuszczalny format
        if not allowed_file(file.filename):
            flash('Nieprawidłowy format pliku! Dopuszczalne to: .txt, .pdf, .png, .jpg, .jpeg, .gif')
            return redirect(url_for('files'))

        return redirect(url_for('files'))

# Import kluczy    
@app.route('/uploadkeys', methods=['POST'])
def uploadkeys():
    # Sprawdzenie, czy wybrano plik
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("Nie wybrano żadnego klucza!")
            return redirect(url_for('login'))
        
        file = request.files['file']
        
        # Sprawdzenie, czy wybrano plik
        if file.filename == "":
            flash("Nie wybrano żadnego klucza!")
            return redirect(url_for('login'))
        
        # Sprawdzenie czy plik ma dopuszczalny format        
        if file and allowed_key(file.filename):
            file_data = file.read().decode("utf-8")
            import_result = gpg.import_keys(file_data)
            flash('Pomyślnie zaimportowano klucz! Teraz możesz się zalogować.')
            return redirect(url_for('login'))
        
        # Definicja akcji, gdy nie wybrano pliku albo plik ma niedopuszczalny format        
        if not allowed_key(file.filename):
            flash('Nieprawidłowy format klucza!')
            return redirect(url_for('login'))

    return redirect(url_for('login'))

# Usuwanie plików 
@app.route('/delete', methods=['POST'])
@login_required
def delete():
    # Sprawdzenie, czy użytkownik ma uprawnienia administratora
    with admin_permission.require(http_exception=403):
        key = request.form['key']

        my_bucket = get_bucket()
        my_bucket.Object(key).delete()

        flash('Pomyślnie usunięto plik!')
        return redirect(url_for('files'))

# Pobieranie pliku    
@app.route('/downloadfile', methods=['POST'])
@login_required
def downloadfile():
    key = request.form['key']

    my_bucket = get_bucket()
    file_obj = my_bucket.Object(key).get()

    return Response(
        file_obj['Body'].read(),
        mimetype='text/plain',
        headers={"Content-Disposition": "attachment;filename={}".format(key)}
    )

# Definicja uprawnień administratora    
@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    identity.user = current_user
    if current_user.is_authenticated:
        if getattr(current_user, 'id') == 26:
            identity.provides.add(RoleNeed('admin'))

# Definicja komunikatu, gdy użytkownik nie ma uprawnień
@app.errorhandler(403)
def noadmin(e):
    flash('Nie masz uprawnień do wykonania tej czynności.')
    return redirect(url_for('files'))