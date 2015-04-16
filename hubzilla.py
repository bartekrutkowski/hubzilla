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
syslog.setFormatter(logging.Formatter("hubzilla[%(process)d]: %(levelname)s - %(message)s "
                    "[in %(pathname)s:%(lineno)d]"))
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


def make_bug(pull_req):
    """Makes problem_report dict from pull_request data sent by GitHub hook."""

    bug = {
        "product": "Ports & Packages",
        "component": "Individual Port(s)",
        "version": "Latest",
        "summary": "GitHub Pull Request #{number}: {title}".format(
            number=pull_req['pull_request']['number'],
            title=pull_req['pull_request']['title']),
        "description": "{description}\nBy: {name}({name_url})".format(
            description=pull_req['pull_request']['body'],
            name=pull_req['pull_request']['user']['login'],
            name_url=pull_req['pull_request']['user']['url']),
        "url": "{url}".format(url=pull_req['pull_request']['html_url'])
    }
    return bug


def make_patch(pr_id, data):
    """Makes patch dictionary."""

    patch = {
        "ids": [pr_id],
        "is_patch": "true",
        "summary": "Patch from GitHub Pull Request",
        "data": data,
        "file_name": "pull_request.diff"
    }
    return patch


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
        pull_req = json.loads(request.data)
    except (ValueError, TypeError):
        log.error("No JSON in pull request data")
        abort(500)
    if not (pull_req['action'] == 'opened' and
            pull_req['pull_request']['state'] == 'open'):
        log.error("The pull-request is already closed")
        abort(500)

    problem_report = make_bug(pull_req)
    url = '{url}/bug'.format(url=conf.get('bugzilla', 'url'))
    params = {"api_key": "{key}".format(key=conf['bugzilla']['api_key'])}
    try:
        pr_id = requests.post(url, params=params, json=problem_report).json()['id']
    except Exception as e:
        log.error("Posting PR failed: {e}".format(e=e))
        abort(500)

    url = '{url}/bug/{pr_id}/attachment'.format(
        url=conf.get('bugzilla', 'url'),
        pr_id=pr_id)
    params = {"api_key": conf['bugzilla']['api_key']}
    data = make_patch(
        pr_id,
        requests.get(pull_req['pull_request']['diff_url']).text)
    file_id = requests.post(url, params=params, json=data)

    comment = {"body": conf.get('github', 'comment').format(pr_id=pr_id)}

    comment_pull_request = requests.post(
        '{url}?access_token={token}'.format(
            url=pull_req['pull_request']['comments_url'],
            token=conf.get('github', 'token')),
        data=json.dumps(comment))
    close_pull_request = requests.patch(
        '{url}?access_token={token}'.format(
            url=pull_req['pull_request']['url'],
            token=conf.get('github', 'token')),
        data='{"state": "closed"}')
    return make_response('OK', 200)


if __name__ == '__main__':
    conf = configparser.RawConfigParser()
    conf.read(os.environ['HUBZILLA_CONFIG'])

    app.run(host=conf.get('app', 'listen_addr'),
            port=conf.getint('app', 'listen_port'), debug=True)
