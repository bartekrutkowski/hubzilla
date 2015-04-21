# -*- coding: utf-8 -*-

import configparser
import os
import json
import logging
import requests

from logging.handlers import SysLogHandler
from flask import Flask, abort, make_response, request
from functools import wraps
from hmac import new
from hashlib import sha1


app = Flask(__name__)
app.secret_key = os.urandom(128)

syslog = SysLogHandler(address='/dev/log')
syslog.setLevel(logging.INFO)
syslog.setFormatter(logging.Formatter(
                    "hubzilla[%(process)d]: %(levelname)s - "
                    "%(message)s [in %(pathname)s:%(lineno)d]"))
app.logger.addHandler(syslog)
log = app.logger

conf = configparser.RawConfigParser()
conf.read(os.environ['HUBZILLA_CONFIG'])


def to_unicode(text, encoding='utf-8'):
    """Convert the text to unicode if it is not unicode already."""

    if isinstance(text, basestring) and not isinstance(text, unicode):
        return text.decode(encoding)
    else:
        return text


def build_problem_report(req_data):
    """Returns problem report dict from req_data sent by GitHub hook."""
    return {
        "product": "Ports & Packages",
        "component": "Individual Port(s)",
        "version": "Latest",
        "summary": "GitHub Pull Request #{number}: {title}".format(
            number=req_data['pull_request']['number'],
            title=req_data['pull_request']['title']),
        "description": "{description}\nBy: {name}({name_url})".format(
            description=req_data['pull_request']['body'],
            name=req_data['pull_request']['user']['login'],
            name_url=req_data['pull_request']['user']['url']),
        "url": "{url}".format(url=req_data['pull_request']['html_url'])
    }


def make_patch(pr_id, data):
    """Makes patch dictionary."""
    return {
        "ids": [pr_id],
        "is_patch": "true",
        "summary": "Patch from GitHub Pull Request",
        "data": data,
        "file_name": "pull_request.diff"
    }


def post_comment(req_data, problem_report_id):
    """Posts comment to GitHub pull request."""
    comment = {"body": conf.get('github', 'comment').format(
                                                    pr_id=problem_report_id)}
    requests.post(
        '{url}?access_token={token}'.format(
            url=req_data['pull_request']['comments_url'],
            token=conf.get('github', 'token')),
        data=json.dumps(comment))
    return


def close_pull_request(req_data):
    """Closes GitHub pull request."""
    requests.patch(
        '{url}?access_token={token}'.format(
            url=req_data['pull_request']['url'],
            token=conf.get('github', 'token')),
        data='{"state": "closed"}')
    return


def upload_patch(req_data, problem_report_id):
    """Uploads diff from GitHub pull request into problem report."""
    url = '{url}/bug/{id}/attachment'.format(
        url=conf.get('bugzilla', 'url'),
        id=problem_report_id)
    params = {"api_key": conf['bugzilla']['api_key']}
    data = make_patch(
        problem_report_id,
        requests.get(req_data['pull_request']['diff_url']).text)
    requests.post(url, params=params, json=data)
    return


def open_problem_report(problem_report):
    """Creates problem report in Bugzilla and returns its id."""
    url = '{url}/bug'.format(url=conf.get('bugzilla', 'url'))
    params = {"api_key": "{key}".format(key=conf['bugzilla']['api_key'])}
    try:
        result = requests.post(url, params=params, json=problem_report)
    except Exception as e:
        log.error("Posting PR failed: {e}".format(e=e))
        abort(500)
    return result.json()['id']


def authorize(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            gh_sig = request.headers.get('X-Hub-Signature').split('=')
        except AttributeError as e:
            log.error("Missing X-Hub-Signature: {e}".format(e=e))
            abort(401)
        if gh_sig[0] != 'sha1' or len(gh_sig[1]) is not 40:
            log.error("Malformed X-Hub-Signature")
            abort(401)
        else:
            gh_secret = str(conf.get('github', 'secret'))
            req_data = request.get_data()
            req_sig = new(gh_secret, req_data, sha1).hexdigest()
            if req_sig != gh_sig[1]:
                log.error("X-Hub-Signature mismatch")
                abort(401)
            else:
                return f(*args, **kwargs)
    return decorated_function


@app.route('/pull-request', methods=['POST'])
@authorize
def index():
    try:
        request_data = json.loads(request.data)
    except (ValueError, TypeError):
        log.error("No JSON in pull request data")
        abort(500)
    if not (request_data['action'] == 'opened' and
            request_data['pull_request']['state'] == 'open'):
        log.error("The pull-request is already closed")
        abort(500)

    problem_report = build_problem_report(request_data)
    problem_report_id = open_problem_report(problem_report)
    upload_patch(request_data, problem_report_id)
    post_comment(request_data, problem_report_id)
    close_pull_request(request_data)

    return make_response('OK', 200)


if __name__ == '__main__':
    conf = configparser.RawConfigParser()
    conf.read(os.environ['HUBZILLA_CONFIG'])

    app.run(host=conf.get('app', 'listen_addr'),
            port=conf.getint('app', 'listen_port'), debug=True)
