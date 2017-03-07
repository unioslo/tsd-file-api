
"""Testing Transfer-Encoding: chunked for file uploads."""

from flask import Flask, request, redirect, url_for, jsonify, g, render_template

app = Flask(__name__)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response

@app.route('/test-upload')
def show_html():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5555, debug=True)
