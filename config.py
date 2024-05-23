import os

basedir = os.path.abspath(os.path.dirname(__file__))

# Database configuration
class Config(object):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# Secret key configuration
class ProductionConfig(Config):
    SECRET_KEY = os.environ.get('SECRET_KEY')

class DevelopmentConfig(Config):
    SECRET_KEY = 'secret-key'

# Configuration for the current environment
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}