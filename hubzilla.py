import os
import bugzilla
import io
import json
import requests

import configparser
from flask import abort, Flask, request
from functools import wraps

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
        'summary': 'GITHUB - IGNORE: Pull request #{number}: {title}'.format(
            number=pull_request['pull_request']['number'],
            title=pull_request['pull_request']['title']),
        'description': '{description}\nBy: {name}({name_url})'.format(
            description=pull_request['pull_request']['body'],
            name=pull_request['pull_request']['user']['login'],
            name_url=pull_request['pull_request']['user']['url']),
        'url': '{url}'.format(url=pull_request['pull_request']['html_url'])
    }
    return problem_report


def verify_request(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            github_signature = request.headers.get('X-Hub-Signature')
        except KeyError, e:
            print "ERROR: Received request without X-Hub-Signature: {error}".format(error=e)
            abort(401)
        print github_signature
    return decorated_function


@app.route('/pull-request', methods=['POST'])
@verify_request
def index():
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
    comment = {"body": "This repository is a read only mirror of"
        "official FreeBSD SVN repository. Your pull-request has been "
        "transferred into FreeBSD bug tracker here:"
        "https://bugs.freebsd.org/bugzilla/show_bug.cgi?"
        "id={problem_report_id} where you can work with the FreeBSD "
        "community on it."
        "This pull request is closed automatically.".format(
            problem_report_id=problem_report.id)}
    comment_pull_request = requests.post(
        '{url}?access_token={token}'.format(
            url=pull_request['pull_request']['comments_url'],
            token=conf.get('github', 'token')),
        data=json.dumps(comment))
    close_pull_request = requests.patch(
        '{url}?access_token={token}'.format(
            url=pull_request['pull_request']['url'],
            token=conf.get('github', 'token')),
        data='{"state": "closed"}')
    print close_pull_request


if __name__ == '__main__':
    conf = configparser.RawConfigParser()
    conf.read(os.environ['HUBZILLA_CONFIG'])

    app.run(host=conf.get('app', 'listen_addr'),
            port=conf.getint('app', 'listen_port'), debug=True)
