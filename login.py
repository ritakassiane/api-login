import flask
from flask import jsonify
from flask import abort
from flask import make_response
from requests.models import ProtocolError
from flask import request
import requests
import json
from flask_cors import CORS



app = flask.Flask(__name__)
CORS(app)
app.config["DEBUG"] = True






url = 'http://localhost:3021/graphql'
jsonToken = {
    'token': 'token',
    'pk_code': 'pk_code'
}

# A função abaixo implementa a query Current Person e retorna o pk code do usuário logado
def pk_code(token):
    #headers = {'Authorization': token}
    current_person = """query{
        currentPerson{
            pk_code
        }
    } 
    """
    print(current_person)
    headers = {'Authorization': 'token %s' % token}
    r = requests.post(url, json={'query': current_person}, headers=headers)
    print(r.json())
    if 'errors' not in (r.json()):
        pk_code = r.json()['data']['currentPerson']['pk_code']
        return pk_code, r.status_code
    else:
        r.status_code = 400
        return 'err', r.status_code



# A função abaixo recebe as credenciais do usuário e retorna a mutation como o email e senha fornecido
def login_mutation(email, password):
    emailStr = '"{}"'.format(email)
    passwordStr = '"{}"'.format(password)
    print(emailStr, passwordStr)
    mutation = """mutation{    
    createToken(email: """+emailStr+ """ password: """+passwordStr+""")
    {token}
    }
    """
    print(mutation)
    return mutation

# A funlção dict_token recebe um dicionáiro e um token, substituindo o valor do token existente pelo token fornecido.
def dict_token(dict, token, pk_code):
    if (dict['token'] and dict['pk_code']):
        dict['token'] = token
        dict['pk_code'] = pk_code
    else:
        print('The key does not exist')
    return dict



# Exibindo o error 400 de maneira elegante
# @app.errorhandler(400)
# def not_found(error):
#     return make_response(jsonify({'error': 'Not Found'}, 400))


def post_login(req):
    email, password = req['email'], req['password']
    mutation = login_mutation(email, password)
    r = requests.post(url, json={'query': mutation})
    print(r.json())
    if 'errors' not in (r.json()):
        return r.json(), r.status_code
    else:
        r.status_code = 400
        return 'err', r.status_code


@app.route('/', methods=['GET'])
def getToken():
    return jsonify(jsonToken)


@app.route('/login', methods=['POST'])
def postLogin():
    email = request.json.get('email')
    password = request.json.get('password')
    req = {'email': email, 'password':password}
    result_post_on_gql = post_login(req) # resultado do post feito na API base

    if not request.json or (result_post_on_gql[1] == 400):
        return make_response(jsonify({'error': 'Unauthorized access'}), 401)    

    elif result_post_on_gql[1] == 200:
        token = result_post_on_gql[0]['data']['createToken']['token']
        pkcode = pk_code(token)
        print('Passou por aqui')
        print(pkcode[0])
        newJsonToken = dict_token(jsonToken, token, pkcode[0])
        return jsonify(newJsonToken), 201
    else:
        return 'Empty' 


app.run()