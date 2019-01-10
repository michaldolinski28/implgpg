import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    GPG_BINARY='gpg'
    LOG_TO_STDOUT = os.environ.get('LOG_TO_STDOUT')
    S3_BUCKET = os.environ.get('S3_BUCKET')
    S3_KEY = os.environ.get('AWS_ACCESS_KEY_ID')
    S3_SECRET = os.environ.get('AWS_SECRET_ACCESS_KEY')
    S3_LOCATION = 'http://{}.s3.amazonaws.com/'.format(S3_BUCKET)
    ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
    KEY_EXTENSION = set(['asc'])