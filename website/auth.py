from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from .models import User
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email =request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email = email).first()
        if user:
            if check_password_hash(user.password,password):
                flash("Logged In Successfully!", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Wrong Password!', category='error')
        else:
            flash('User Doesn\'t Exist!', category = 'error')

    return render_template("login.html",user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up',methods=['GET', 'POST'])
def sign_up():

    if request.method == 'POST':
        email=request.form.get('email')
        first_name=request.form.get('first_name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email address already exists', category='error')
        elif len(email)<3:
            flash('Give big email!',category='error')
        elif len(first_name) <2:
            flash('Name must be more than 1 character ', category = 'error')
        elif len(password) <8:
            flash('Password must be 8 chaarcters LONG', category = 'error')
        elif password != confirm_password:
            flash('Passwords Don\'t match', category = 'error')
        else:
            newuser =User(email=email,first_name=first_name, password=generate_password_hash(password,method='scrypt'))
            db.session.add(newuser)
            db.session.commit()
            login_user(newuser, remember=True)
            flash('Account successfully created!', category = 'success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html",user=current_user)
