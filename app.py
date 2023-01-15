import logging
import hmac
from json import loads, dumps
from sys import stderr, hexversion
from os.path import abspath, normpath, dirname, join
from ipaddress import ip_address, ip_network
import requests
from flask import Flask, request, abort
import subprocess


logging.basicConfig(
     filename='log_file.log',
     level=logging.INFO,
     format= '%(asctime)s [%(process)d] [%(levelname)s] - %(message)s',
     datefmt='%Y-%m-%d %H:%M:%S'
)

application = Flask(__name__)


@application.route('/', methods=['GET', 'POST'])
def index():
    """
    Main WSGI application entry.
    """

    path = normpath(abspath(dirname(__file__)))

    # Only POST is implemented
    if request.method != 'POST':
        abort(501)

    # Load config
    with open(join(path, 'config.json'), 'r') as cfg:
        config = loads(cfg.read())

    # Allow Github IPs only
    if config.get('github_ips_only', True):
        src_ip = ip_address(request.access_route[0])

        whitelist = requests.get('https://api.github.com/meta', timeout=10).json()['hooks']

        for valid_ip in whitelist:
            if src_ip in ip_network(valid_ip):
                break
        else:
            logging.error('IP %s not allowed', src_ip)
            abort(403)

    # Enforce secret
    secret = config.get('enforce_secret', '')
    if secret:
        # Only SHA1 is supported
        header_signature = request.headers.get('X-Hub-Signature')
        if header_signature is None:
            abort(403)

        sha_name, signature = header_signature.split('=')
        if sha_name != 'sha1':
            abort(501)

        # HMAC requires the key to be bytes, but data is string

        bytes_secret = secret.encode()
        mac = hmac.new(bytes_secret, msg=request.data, digestmod='sha1')

        # Python prior to 2.7.7 does not have hmac.compare_digest
        if hexversion >= 0x020707F0:
            if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
                abort(403)
        else:
            # What compare_digest provides is protection against timing
            # attacks; we can live without this protection for a web-based
            # application
            if str(mac.hexdigest()) != str(signature):
                abort(403)

    # Implement ping
    event = request.headers.get('X-GitHub-Event', 'ping')
    if event == 'ping':
        return dumps({'msg': 'pong'})

    # Gather data
    try:
        payload = request.get_json()
    except Exception:
        logging.warning('Request parsing failed')
        abort(400)

    # Determining the branch is tricky, as it only appears for certain event
    # types an at different levels
    branch = None
    try:
        # Case 1: a ref_type indicates the type of ref.
        # This true for create and delete events.
        if 'ref_type' in payload:
            if payload['ref_type'] == 'branch':
                branch = payload['ref']

        # Case 2: a pull_request object is involved. This is pull_request and
        # pull_request_review_comment events.
        elif 'pull_request' in payload:
            # This is the TARGET branch for the pull-request, not the source
            # branch
            branch = payload['pull_request']['base']['ref']

        elif event in ['push']:
            # Push events provide a full Git ref in 'ref' and not a 'ref_type'.
            branch = payload['ref'].split('/', 2)[2]

    except KeyError:
        # If the payload structure isn't what we expect, we'll live without
        # the branch name
        pass

    # All current events have a repository, but some legacy events do not,
    # so let's be safe
    name = payload['repository']['name'] if 'repository' in payload else None

    meta = {
        'name': name,
        'branch': branch,
        'event': event
    }
    logging.info('Metadata:\n%s', dumps(meta))

    # Skip push-delete
    if event == 'push' and payload['deleted']:
        logging.info('Skipping push-delete event for %s', dumps(meta))
        return dumps({'status': 'skipped'})

    to_run_scripts = list(filter(
        lambda x: x["name"] == name and x["branch"] == branch and x["event"] == event,
        config.get("actions", [])
    ))

    logging.info("srcipts to run %s\nfor %s" , to_run_scripts, meta)

    for script in to_run_scripts:
        logging.info( "Running script %s", script["run"])
        output = subprocess.run(script["run"], stdout=subprocess.PIPE, text=True, check=False)
        logging.info("srcipt output: %s",  output.stdout)
        # if output is not None:
        #     logging.info( output.decode() )
        # else:
        #     logging.info( "No returned value" )

    return dumps({'status': 'done'})

if __name__ == '__main__':
    application.run(debug=True, host='0.0.0.0', port=8000)