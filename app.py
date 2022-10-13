import email
from email.message import EmailMessage
import random
import smtplib
from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    number = db.Column(db.String(300), nullable=False)
    valido = db.Column(db.String(1), default='N', nullable=False)

class CambioPassForm(FlaskForm):
    auth = StringField(validators=[
                             InputRequired(), Length(min=3, max=100)], render_kw={"placeholder": "auth"})
    pass1 = StringField(validators=[
                             InputRequired(), Length(min=3, max=100)], render_kw={"placeholder": "pass1"})

    pass2 = StringField(validators=[
                            InputRequired(), Length(min=3, max=100)], render_kw={"placeholder": "pass2"})                            
    submit = SubmitField('Cambiar')

class RecuperarForm(FlaskForm):
    email = StringField(validators=[
                             InputRequired(), Length(min=3, max=100)], render_kw={"placeholder": "email"})
    submit = SubmitField('Enviar')

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    email = StringField(validators=[
                             InputRequired(), Length(min=3, max=100)], render_kw={"placeholder": "email"})

    submit = SubmitField('Crear')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That email already exists. Please choose a different one.')

class DasboarForm(FlaskForm):
    asunto = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "asunto"})

    email = StringField(validators=[
                             InputRequired(), Length(min=3, max=100)], render_kw={"placeholder": "email"})

    conten = StringField(validators=[
                             InputRequired(), Length(min=3, max=500)], render_kw={"placeholder": "contenido"})

    submit = SubmitField('Enviar')

class LoginForm(FlaskForm):
    email = StringField(validators=[
                           InputRequired(), Length(min=4, max=100)], render_kw={"placeholder": "email"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

#---------------------------------------------------------------------------------
@app.route('/')
@app.route('/index')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        print(user)
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = DasboarForm()
    if form.validate_on_submit():
        content=form.conten.data
        email=form.email.data
        subject=form.asunto.data
        send_email('', receiver=email, subject=subject, message=content)
        return render_template( 'dashboard.html', form=form )
    return render_template( 'dashboard.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/cambio_pass', methods=('GET', 'POST'))          		
def cambio_pass(): 
    form = CambioPassForm()    
    if request.method == 'POST':
        #if form.validate_on_submit():
        auth=form.auth.data
        pass1=form.pass1.data
        pass2=form.pass1.data

        if  pass1 != pass2:
            return redirect('/cambio_pass?auth=' + auth)

        existing_user = User.query.filter_by(number=auth).first()
        existing_user.password = bcrypt.generate_password_hash(pass1)
        db.session.commit()

        return render_template( 'index.html')
    auth = request.args.get('auth')
    return render_template( 'cambio_pass.html',auth = auth, form=form )

@app.route('/recupero', methods=('GET', 'POST'))  
def recupero():
    form = RecuperarForm()
    if form.validate_on_submit():
        number = hex(random.getrandbits(512))[2:]
        email=form.email.data

        existing_user = User.query.filter_by(email=email).first()
        existing_user.number = number
        db.session.add(existing_user)
        db.session.commit()
        content = 'Hola, Bienvenido!, cambie su contraseña en el siguente link  http://127.0.0.1:5000/cambio_pass?auth=' + number
        send_email('', receiver=email, subject='cambie su contraseña en Message.com', message=content)
        return render_template( 'index.html' )
    return render_template( 'recupero.html', form=form)

@app.route('/activate', methods=('GET', 'POST'))          		
def activate(): 
        print("existing_user")
        auth = request.args.get('auth')
        existing_user = User.query.filter_by(number=auth).first()
        existing_user.valido = 'S'
        db.session.add(existing_user)
        db.session.commit()

        return render_template( 'index.html' )

@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        number = hex(random.getrandbits(512))[2:]
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data, number=number, valido="N")
        
        content = 'Hola, Bienvenido!, Active su cuenta en el siguente link  http://127.0.0.1:5000/activate?auth=' + number
        send_email('', receiver=form.email.data, subject='Activa tu cuenta en Message.com', message=content)

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = 'rcastilloe@uninorte.edu.co'
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)
    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login( 'rcastilloe@uninorte.edu.co', 'Castillo2022')
    smtp.sendmail( 'rcastilloe@uninorte.edu.co' , receiver, email.as_string())
    smtp.quit()

if __name__ == "__main__":
    app.run(debug=True)
