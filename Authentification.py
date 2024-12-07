# %%
from flask import Flask, render_template, flash, request, redirect, url_for, session, logging, jsonify, send_file
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from functools import wraps
from passlib.hash import sha256_crypt
from wtforms import SelectField
import pyodbc

# %%
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configuration pour Azure SQL Database
server = 'authentificationserver.database.windows.net'  # Remplacez par le nom de votre serveur Azure
database = 'Authentification001'  # Remplacez par le nom de votre base de données
username = 'authentificationadmin'  # Remplacez par votre nom d'utilisateur Azure
password = 'HelloWorld001'  # Remplacez par votre mot de passe Azure
driver = '{ODBC Driver 18 for SQL Server}'  # Assurez-vous que le pilote ODBC est installé 

# Fonction pour obtenir une connexion
def get_db_connection():
    conn = pyodbc.connect(
        f'DRIVER={driver};SERVER={server};PORT=1433;DATABASE={database};UID={username};PWD={password}'
    )
    return conn

# %%
@app.route('/')
def index():
    return render_template('index.html')

# %%
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=25)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    role = SelectField('Role', choices=[('admin', 'Administrateur'), ('student', 'Étudiant')], validators=[validators.DataRequired()])
    teaching_reg_number = StringField('Matricule d\'enseignement', [
        validators.Optional(),
        validators.Length(max=15)
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Les mots de passe ne correspondent pas')
    ])
    confirm = PasswordField('Confirm Password')

# %%
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        role = form.role.data
        username = form.username.data
        password = sha256_crypt.hash(str(form.password.data))
        
        if role == 'admin':
            teaching_reg_number = form.teaching_reg_number.data
            if not teaching_reg_number:
                flash('Matricule d\'enseignement requis pour les administrateurs', 'danger')
                return render_template('register.html', form=form)

        conn = get_db_connection()
        cur = conn.cursor()

        # Vérification de l'existence du nom d'utilisateur
        cur.execute("SELECT * FROM users WHERE username = ?", [username])
        user = cur.fetchone()
        if user:
            flash('Nom d\'utilisateur déjà pris', 'danger')
            conn.close()
            return render_template('register.html', form=form)

        # Vérification de l'existence de l'email
        cur.execute("SELECT * FROM users WHERE email = ?", [email])
        user = cur.fetchone()
        if user:
            flash('Email déjà utilisé', 'danger')
            conn.close()
            return render_template('register.html', form=form)

        # Insertion de l'utilisateur dans la base de données
        if role == 'admin':
            cur.execute(
                "INSERT INTO users (name, email, username, password, role, teaching_reg_number) VALUES (?, ?, ?, ?, ?, ?)",
                (name, email, username, password, role, teaching_reg_number)
            )
        else:
            cur.execute(
                "INSERT INTO users (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)",
                (name, email, username, password, role)
            )
        
        conn.commit()
        conn.close()

        flash('Vous êtes maintenant inscrit et pouvez vous connecter', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

# %%
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Non autorisé, veuillez vous connecter', 'danger')
            return redirect(url_for('login'))
    return wrap

# %%
def admin_only(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Vous devez vous connecter', 'danger')
            return redirect(url_for('login'))
        
        username = session.get('username')
        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Vérifiez si l'utilisateur est administrateur
            cur.execute("SELECT role FROM users WHERE username = ?", [username])
            user = cur.fetchone()
            conn.close()
            if user and user[0] == 'admin':  # Assurez-vous que la colonne `role` est la première
                return f(*args, **kwargs)
            else:
                flash('Accès réservé aux administrateurs', 'danger')
                return redirect(url_for('login'))
        except Exception as e:
            flash('Erreur lors de la vérification des permissions', 'danger')
            print(f"Erreur : {e}")
            return redirect(url_for('login'))
    
    return wrap

# %%
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", [username])
        user = cur.fetchone()
        conn.close()
        
        if user:
            password = user[4]  # Assuming password is in the 5th column
            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = username
                flash('Vous êtes maintenant connecté', 'success')
                return redirect(url_for('index'))
            else:
                flash('Mot de passe invalide', 'danger')
                return render_template('login.html')
        else:
            flash('Nom d\'utilisateur introuvable', 'danger')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Vous êtes maintenant déconnecté', 'success')
    return redirect(url_for('index'))

# %%
if __name__ == '__main__':
    app.run(debug=True)