from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required
from flask_sqlalchemy import SQLAlchemy
from admin.forms import UserAddEditForm
import uuid
from faker import Faker
from datetime import datetime
from app import db
#from model.user_model import User
from models.user import UserApi


admin_bp = Blueprint(
    'admin',
    __name__,
    template_folder='templates',
    static_folder='static'
)


@admin_bp.route('/')
#@login_required
def index():
    return render_template('admin/main.html')

@admin_bp.route('/user_main')
#@login_required
def user_main():
    users = UserApi.query.limit(20).all()
    return render_template('admin/user/user_main.html', users=users)

@admin_bp.route('/user_main/add', methods=['GET', 'POST'])
#@login_required
def user_add():
    """
    fake = Faker()
    me = User(id=103, uuid=str(uuid.uuid4()), email=fake.email(),
                 password_hash='password',
                 access_token='asdasd',
                 refresh_token='asdasdasd',
                 created_at=datetime.now())
    db.session.add(me)
    db.session.commit()
    """
    if request.method == 'POST':
        #check_database = User.query.filter_by(email=request.form['email']).first()
        #if check_database:
        #    flash('Email is already exists')

        user = UserApi(uuid=str(uuid.uuid4()), email='emailyyy', password_hash='password')
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('admin.user_main'))

    return render_template('admin/user/user_add_edit.html', form=UserAddEditForm())

@admin_bp.route('/user_main/<uuid>', methods=['GET', 'POST'])
#@login_required
def user_edit(uuid):
    user = UserApi.query.filter_by(uuid=uuid).first()
    form = UserAddEditForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            post = {}
            post['email'] = request.form['email']
            post['password'] = request.form['password']
            db.session.query(User).filter_by(uuid=uuid).update(post)
            return redirect('/user_main')
        else:
            flash(form.validate())
    return render_template('admin/user/user_add_edit.html', form=form, user=user)

@admin_bp.route('/user_main/<uuid>/delete', methods=['POST'])
def user_delete(uuid):
    user = UserApi.query.filter_by(uuid=uuid).first()
    db.session.delete(user)
    db.session.commit()
    return db
    return redirect('/user_main')