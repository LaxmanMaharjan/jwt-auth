import jwt
import requests

from flask.json import jsonify

from jwt import PyJWKClient
from datetime import datetime, timedelta

from jwt import jwks_client
from . import app, db, bcrypt

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate

class User(db.Model):
    """User model for storing necessary credentials"""
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    number = db.Column(db.String(10), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, name, number, email, password, location):
        self.email = email
        self.name = name
        self.password = bcrypt.generate_password_hash(password, app.config.get('BCRYPT_LOG_ROUNDS')).decode()
        self.location = location
        self.number = number    
        self.registered_on = datetime.now()

    def __str__(self):
        return f"{self.name}:{self.email}"

    def encode_auth_token(self, user_id):
        now = datetime.utcnow()

        try:
            payload ={
                    'iat': now,
                    'exp': (now + timedelta(hours=10)).timestamp(),
                    'sub': user_id
                    }
            with open('server/keys/private_key.pem','r') as file:
                private_key_text = file.read()
    
            private_key = serialization.load_pem_private_key(
                private_key_text.encode(), password=None
            )
            return jwt.encode(payload=payload, key=private_key, algorithm="RS256")
        except Exception as e:
            return e
        

    @staticmethod
    def decode_auth_token(token):
        try:
            print("entering decode")
            unverified_headers = jwt.get_unverified_header(token)
            with open("server/keys/public_key.pem", 'r') as file:
                public_key_text = file.read()

            #public_key = load_pem_x509_certificate(public_key_text.encode()).public_key()

        
            #jwks_client = PyJWKClient(url)
            #signing_key = jwks_client.get_signing_key_from_jwt(token)
    
            # using jwks
            #url = "http://localhost:5000/public/.well-known/jwks.json"
            #print(url)
            #public_keys = requests.get(url=url).json()
            #print("request successfull",public_keys)
            #jwk = public_keys["keys"][0]

            #print("jwk",jwk)

            #public_key = jwt.algorithms.RSAAlgorithms.from_jwk(jwk)

            #print(public_key)
            public_key = public_key_text.encode()

            payload = jwt.decode(
                token,
                key=public_key,
                #key=signing_key.key,
                algorithms = unverified_headers["alg"]
                )
            return payload['sub']
        
        except jwt.ExpiredSignatureError:
            return "Signature expired. Please login again"

        except jwt.InvalidTokenError:
            return "Invalid token. Please login again"

        except FileNotFoundError:
            return "Public key file not found"

class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(1000), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False

