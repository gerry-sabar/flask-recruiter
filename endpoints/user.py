from flask_restplus import Namespace, Resource, fields
from flask_jwt_extended import (
    create_access_token, jwt_required, create_refresh_token,
    jwt_refresh_token_required, get_jwt_identity, get_raw_jwt,
)
import datetime
from flask import request
from app import db
from flask_restplus import Resource, fields
from models.user import UserApi
from app import jwt
from flask import request, jsonify, make_response

api = Namespace('users', description='Users related operations')
user = api.model('UserApi', {
    'uuid': fields.String(required=True, description='User uuid'),
    'email': fields.String(required=True, description='User email'),
    'access_token': fields.String(required=True, description='User access token'),
    'refresh_token': fields.String(required=True, description='User refresh token'),
})

blacklist = set()

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist

resource_fields = api.model('Login', {
    'email': fields.String,
    'password': fields.String,
})
@api.route('/login')
@api.response(404, 'User not found')
class Login(Resource):
    @api.expect(resource_fields)
    def post(self):
        """
        Obtain user details & token
        """
        payload = request.get_json()
        user = UserApi.query.filter_by(email=payload['email']).first()

        if user is not None and user.verify_password(payload['password']):
            access_token_expiry = datetime.timedelta(seconds=10)
            access_token = create_access_token(identity=payload['email'], fresh=True, expires_delta=access_token_expiry)
            refresh_token_expiry = datetime.timedelta(minutes=10)
            refresh_token = create_refresh_token(identity=payload['email'], expires_delta=refresh_token_expiry)
            user.access_token = access_token
            user.refresh_token = refresh_token
            db.session.add(user)
            db.session.commit() #test

            return {
                'uuid': user.uuid,
                'email': user.email,
                'access_token': access_token,
                'refresh_token': refresh_token,
            }

        else:
            return ({ 'message': 'Invalid username/password'},403)

@api.route('/all')
class UserList(Resource):
    #@jwt_required
    @api.marshal_list_with(user)
    def get(self):
        '''Get all users'''
        """
        #contoh blacklist & cek blacklist
        jti = get_raw_jwt()['jti']
        blacklist.add(jti)
        return {'test': check_if_token_in_blacklist(get_raw_jwt())}
        """
        users = UserApi.query.all()
        return users

@api.route('/refresh')
@api.response(404, 'Invalid token')
class RefreshToken(Resource):
    @jwt_refresh_token_required
    @api.marshal_with(user)
    def post(self):
        email = get_jwt_identity()

        if not email:
            return ({ 'status': 'invalid refresh token'},400)

        user = UserApi.query.filter_by(email=email).first()
        access_token_expiry = datetime.timedelta(seconds=10)
        refresh_token_expiry = datetime.timedelta(minutes=10)
        user.access_token = create_access_token(identity=email, fresh=True, expires_delta=access_token_expiry)
        user.refresh_token = create_refresh_token(identity=email, expires_delta=refresh_token_expiry)

        return (user,200)


update_fields = api.model('User', {
    'email': fields.String,
    'password': fields.String,
})
@api.route('/<uuid>')
@api.param('uuid', 'User UUID')
@api.response(404, 'User not found')
class User(Resource):
    @jwt_required
    @api.doc('get_user')
    @api.marshal_with(user)
    def get(self, uuid):
        '''Fetch a user given its UUID'''
        user = UserApi.query.filter_by(uuid=uuid).first()

        if not user:
            return ({ 'status': 'user is not found'},404)

        return (user,200)

    @api.expect(update_fields)
    @api.marshal_with(user)
    def put(self, uuid):
        user = UserApi.query.filter_by(uuid=uuid).first()

        if not user:
            return { 'status': 'user is not found'}

        payload = request.get_json()
        db.session.query(UserApi).filter_by(uuid=uuid).update(payload)
        db.session.commit()

        return user

    def delete(self, uuid):
        user = UserApi.query.filter_by(uuid=uuid).first()

        if not user:
            return { 'status': 'user is not found'}
        db.session.delete(user)
        db.session.commit()
        return ('', 204)