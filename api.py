
""" Taken from http://flask.pocoo.org/docs/0.11/patterns/fileuploads/ """

import jwt
import os
from flask import Flask, request, redirect, url_for
from werkzeug.utils import secure_filename
from flask import send_from_directory

UPLOAD_FOLDER = '/Users/leondutoit/uploaded-files'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv', 'tsv'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 40 * 1024 * 1024 # 40 MB limit

# Need to implement JWT generation and validation
# Get from the APIs or the DB? Which is the better design?
# Also, should the subscriber be notified via one of the APIs?
# Or should the channel be accessed via a db connection?
# For writing get JWT from (public.token)
# For reading get JWT from (reports.token) SAML decryption etc
# For validation, use jwt.verify_jwt, check claims against db? need another role?
def verify_json_web_token(token, key):
    # need to get the key from config
    header, claims = jwt.verify_jwt(token, key, ['HS256'], checks_optional=True)
    # check that their role allows either storing or downloading a file
    return header, claims

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file',
                                    filename=filename))
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form action="" method=post enctype=multipart/form-data>
      <p><input type=file name=file>
         <input type=submit value=Upload>
    </form>
    '''
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

