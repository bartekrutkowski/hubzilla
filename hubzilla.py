import os
import bugzilla
import json

import configparser
from flask import Flask, request

app = Flask('__name__')
app.secret_key = os.urandom(128)
conf = configparser.RawConfigParser()
conf.read(os.environ['GITZILLA_CONFIG'])


def bugzilla_connect():
    bgz = bugzilla.Bugzilla(user=conf.get('bugzilla', 'user'),
                            password=conf.get('bugzilla', 'password'),
                            url=conf.get('bugzilla', 'url'),
                            sslverify=False
                            )
    return bgz


def pr_dict(pull_request):
    pr = {
        'product': 'Ports Tree',
        'component': 'Individual Port(s)',
        'version': 'Latest',
        'summary': 'GITHUB - IGNORE: {title}'.format(title=pull_request['pull_request']['title']),
        'description': '{description}'.format(description=pull_request['pull_request']['body'])
    }
    return pr


@app.route('/pull-request', methods=['POST'])
def index():
    if request.method == 'POST':
        pull_request = json.loads(request.data)
        pr = pr_dict(pull_request)
        bgz = bugzilla_connect()
        bgz.createbug(pr)
    return 'OK'


if __name__ == '__main__':
    conf = configparser.RawConfigParser()
    conf.read(os.environ['GITZILLA_CONFIG'])

    app.run(host=conf.get('app', 'listen_addr'),
            port=conf.getint('app', 'listen_port'), debug=True)
