
""" API to support file uploads into TSD projects via the proxy. """

import sys
import jwt # https://github.com/davedoesdev/python-jwt
import os
import yaml
import psycopg2
import psycopg2.pool
from flask import Flask, request, redirect, url_for, jsonify, g
from werkzeug.utils import secure_filename
from flask import send_from_directory
from werkzeug.formparser import FormDataParser

# add method for handling MIME-type: formdata/encrypted
FormDataParser.parse_functions['multipart/encrypted'] = FormDataParser._parse_multipart

def read_config(file):
    with open(file) as f:
        conf = yaml.load(f)
    return conf


CONF = read_config(sys.argv[1])
UPLOAD_FOLDER = CONF['file_uploads']
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv', 'tsv', 'asc'])
MINCONN = 4
MAXCONN = 10
pool = psycopg2.pool.SimpleConnectionPool(MINCONN, MAXCONN, \
    host=CONF['host'], database=CONF['db'], user=CONF['user'], password=CONF['pw'])
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 40 * 1024 * 1024 # 40 MB limit


def get_dbconn():
    dbconn = getattr(g, 'dbconn', None)
    if db is None:
        conn = pool.getconn()
        dbconn = g.dbconn = conn
    return dbconn


@app.teardown_appcontext
def close_connection(exception):
    dbconn = getattr(g, 'dbconn', None)
    if dbconn is not None:
        dbconn.close()


# support signup through file API too? would make it a standalone component...


def get_upload_token():
    pass


def get_download_token():
    pass


def verify_json_web_token(token, key):
    # need to get the key from config
    header, claims = jwt.verify_jwt(token, key, ['HS256'], checks_optional=True)
    # check that their role allows either storing or downloading a file
    return header, claims


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['POST'])
def upload_file():
    # check credentials
    # request.mimetype - this is e.g. multipart/encrypted
    # request.mimetype_params - includes protocol, boundary
    # after saving file, if mimetype multipart/encrypted
        # do something with it, like decrypt it
        # perhaps only if we also get another custom header like X-Decrypt

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'message': 'file not found'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'message': 'no filename specified'}), 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return jsonify({'message': 'uploaded file'}), 201
        else:
            return jsonify({'message': 'file type not allowed'}), 400


# this should not be exposed via the API
@app.route('/download/<filename>', methods=['GET'])
def uploaded_file(filename):
    # check credentials
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# should not have debug in prod
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
