import os
import bugzilla
import json
import requests

import configparser
from flask import Flask, request

app = Flask('__name__')
app.secret_key = os.urandom(128)
conf = configparser.RawConfigParser()
conf.read(os.environ['HUBZILLA_CONFIG'])


def bugzilla_connect():
    bgz = bugzilla.Bugzilla(user=conf.get('bugzilla', 'user'),
                            password=conf.get('bugzilla', 'password'),
                            url=conf.get('bugzilla', 'url'),
                            sslverify=False
                            )
    return bgz


def fill_problem_report(pull_request):
    problem_report = {
        'product': 'Ports Tree',
        'component': 'Individual Port(s)',
        'version': 'Latest',
        'summary': 'GITHUB - IGNORE: {title}'.format(
            title=pull_request['pull_request']['title']),
        'description': '{description}'.format(
            description=pull_request['pull_request']['body'],
        'url': '{url}'.format(url=pull_request['pull_request']['url'])
    }
    return problem_report


@app.route('/pull-request', methods=['POST'])
def index():
    if request.method == 'POST':
        pull_request = json.loads(request.data)
        problem_report = fill_problem_report(pull_request)
        bgz = bugzilla_connect()
        problem_report_id = bgz.createbug(problem_report)

    return 'OK'


if __name__ == '__main__':
    conf = configparser.RawConfigParser()
    conf.read(os.environ['HUBZILLA_CONFIG'])

    app.run(host=conf.get('app', 'listen_addr'),
            port=conf.getint('app', 'listen_port'), debug=True)
