import os
basedir = os.path.abspath(os.path.dirname(__file__))
#postgres_local_base = 'postgresql://postgres:@localhost/'
#database_name = 'auth_db'

class BaseConfig:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'my_precious')
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4
    #SQLALCHEMY_DATABASE_URI = postgres_local_base + database_name

    SQLALCHEMY_DATABASE_URI = 'postgres://bopntwngefzncl:cab0d33cd159244e6f2df23f9c84ed8625f1d72d7d4524582725ac3085864bfb@ec2-34-236-94-53.compute-1.amazonaws.com:5432/d18sjh3u411v1h'
    JWKS = "/home/laxman/Projects/Python-and-Applications/Flask/jwt-auth/server/public/.well-known"

