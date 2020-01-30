from flask_restplus import Api

from .user import api as user_api

#add api key
authorizations = {
    'apikey' : {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Types in the *'Value'* input box below: **'Bearer &lt;JWT&gt;'**, where JWT is the token"
    }
}

api = Api(
    title='Simple API',
    version='1.0',
    description='A simple demo API',
    authorizations=authorizations,
    security='apikey'
)

api.add_namespace(user_api)
