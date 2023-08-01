from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

# LOGIN CONFIGURATIONS
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    # Passing True or False if the user is authenticated.
    return render_template("index.html", logged_in=current_user.is_authenticated)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash('A user with that email address already exists. Please log in.')
            return redirect(url_for('login'))

        new_user = User(
            email=email,
            name=name,
            password=generate_password_hash(password),
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return render_template("secrets.html")

    return render_template("register.html", logged_in=current_user.is_authenticated)

# by using salting
#
# @app.route('/register', methods=["GET", "POST"])
# def register():
#     if request.method == "POST":
#         # Hashing and salting the password entered by the user
#         hash_and_salted_password = generate_password_hash(
#             request.form.get('password'),
#             method='pbkdf2:sha256',
#             salt_length=8
#         )
#         # Storing the hashed password in our database
#         new_user = User(
#             email=request.form.get('email'),
#             name=request.form.get('name'),
#             password=hash_and_salted_password,
#         )
#
#         db.session.add(new_user)
#         db.session.commit()
#
#         return render_template("secrets.html", name=request.form.get('name'))
#
#     return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('secrets'))
        else:
            flash('Invalid email or password. Please Try again.')

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
def download():
    file_sheet = 'cheat_sheet.pdf'
    return send_from_directory('static/files', file_sheet, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
