import os
import bugzilla
import io
import json
import requests

import configparser
from flask import Flask, request

app = Flask('__name__')
app.secret_key = os.urandom(128)
conf = configparser.RawConfigParser()
conf.read(os.environ['HUBZILLA_CONFIG'])


def bugzilla_connect():
    """Connect to Bugzilla instance and return callable object 'bgz'."""

    bgz = bugzilla.Bugzilla(user=conf.get('bugzilla', 'user'),
                            password=conf.get('bugzilla', 'password'),
                            url=conf.get('bugzilla', 'url'),
                            sslverify=False
                            )
    return bgz


def fill_problem_report(pull_request):
    """Fills problem_report dict from pull_request data sent by GitHub hook."""
    problem_report = {
        'product': 'Ports Tree',
        'component': 'Individual Port(s)',
        'version': 'Latest',
        'summary': 'GITHUB - IGNORE: {title}'.format(
            title=pull_request['pull_request']['title']),
        'description': '{description}'.format(
            description=pull_request['pull_request']['body']),
        'url': '{url}'.format(url=pull_request['pull_request']['html_url'])
    }
    return problem_report


@app.route('/pull-request', methods=['POST'])
def index():
    if request.method == 'POST':
        pull_request = json.loads(request.data)
        problem_report = fill_problem_report(pull_request)
        bgz = bugzilla_connect()
        problem_report = bgz.createbug(problem_report)
        diff_file = io.StringIO(requests.get(
                                pull_request['pull_request']['diff_url']).text)
        file_id = bgz.attachfile(idlist=problem_report.id,
                                 attachfile=diff_file,
                                 name='pull_request.diff',
                                 file_name='pull_request.diff',
                                 is_patch=True,
                                 description='Diff file from pull request')
    return 'OK'


if __name__ == '__main__':
    conf = configparser.RawConfigParser()
    conf.read(os.environ['HUBZILLA_CONFIG'])

    app.run(host=conf.get('app', 'listen_addr'),
            port=conf.getint('app', 'listen_port'), debug=True)
