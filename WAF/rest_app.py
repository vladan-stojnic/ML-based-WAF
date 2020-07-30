'''Implementation of the simple rest service that can be used for testing of the WAF.'''

from flask import Flask

app = Flask(__name__)

@app.route('/srs/api/hello/<string:name>', methods=['GET', 'POST'])
def hello(name):
    return 'Hello, ' + name + '!'

if __name__ == '__main__':
    app.run(debug=True)