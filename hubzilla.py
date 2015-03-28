# -*- coding: utf-8 -*-

import os
import json
import requests

import configparser
from flask import Flask, abort, make_response, request
from functools import wraps
from hmac import new
from hashlib import sha1


app = Flask('__name__')
app.secret_key = os.urandom(128)
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


def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            gh_sig = request.headers.get('X-Hub-Signature').split('=')
        except AttributeError, e:
            print "ERROR: Request missing X-Hub-Signature! {e}".format(e=e)
            abort(401)
        if gh_sig[0] != 'sha1' or len(gh_sig[1]) is not 40:
            print "ERROR: Request malformed X-Hub-Signature!"
            abort(401)
        else:
            gh_secret = str(conf.get('github', 'secret'))
            req_data = request.get_data()
            req_sig = new(gh_secret, req_data, sha1).hexdigest()
            if req_sig != gh_sig[1]:
                print "ERROR: X-Hub-Signature mismatch!"
                abort(401)
            else:
                return f(*args, **kwargs)
    return decorated_function


@app.route('/pull-request', methods=['POST'])
@auth_required
def index():
    try:
        pull_req = json.loads(request.data)
    except (ValueError, TypeError):
        print "ERROR: pull-request data was not JSON."
        abort(500)
    if pull_req['action'] == 'opened' and pull_req['pull_request']['state'] == 'open':
        problem_report = make_bug(pull_req)
        post_url = '{url}/bug'.format(url=conf.get('bugzilla', 'url'))
        post_params = {"api_key": "{key}".format(key=conf['bugzilla']['api_key'])}
        try:
            pr_id = requests.post(post_url, params=post_params, json=problem_report).json()['id']
        except Exception as error:
            print "ERROR: posting PR failed."
            print error
            abort(500)

        post_url = '{url}/bug/{pr_id}/attachment'.format(
                                                    url=conf.get('bugzilla', 'url'),
                                                    pr_id=pr_id)
        post_params = {"api_key": conf['bugzilla']['api_key']}
        post_data = make_patch(pr_id, requests.get(pull_req['pull_request']['diff_url']).text)
        file_id = requests.post(post_url, params=post_params, json=post_data)

        comment = {"body": "This repository is a read only mirror of "
                   "official FreeBSD SVN repository. Your pull-request has "
                   "been transferred into FreeBSD bug tracker here: "
                   "https://bugs.freebsd.org/bugzilla/show_bug.cgi?"
                   "id={pr_id} where you can work with the FreeBSD community "
                   "on resolving your Problem Report.\n\n"
                   "This pull request is closed automatically.".format(pr_id=pr_id)}

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
    else:
        print "ERROR: the pull-request is already closed."
        abort(500)


if __name__ == '__main__':
    conf = configparser.RawConfigParser()
    conf.read(os.environ['HUBZILLA_CONFIG'])

    app.run(host=conf.get('app', 'listen_addr'),
            port=conf.getint('app', 'listen_port'), debug=True)
