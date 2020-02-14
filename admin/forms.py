from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, validators
from wtforms.validators import DataRequired, Email, Length

class UserAddEditForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message='Please enter a valid email address'),
        Email(message='Please enter a valid email address')
    ])

    password = PasswordField('Password', validators=[validators.length(min=6)])
    submit = SubmitField('Sign In')