from flask import Blueprint, render_template, request, flash, redirect
from auth.forms import LoginForm
from flask_login import login_required, login_user, current_user, logout_user
from models.user import UserApi

auth_bp = Blueprint(
    'auth',
    __name__,
    template_folder='templates',
    static_folder='static'
)

@auth_bp.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = UserApi.query.filter_by(email=request.form['email']).first()
            if user is not None and user.verify_password(request.form['password']):
                login_user(user)
                return redirect('/')
            else:
                form.email.errors.append('This account is not found')
        else:
            flash(form.validate())
    return render_template('auth/login.html', form=form)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    return 'register'


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')