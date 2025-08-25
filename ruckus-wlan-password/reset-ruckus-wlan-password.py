#!/usr/bin/env python3

import json
import string
import urllib3
import smtplib
import logging
import argparse
import requests

from pprint import pformat
from email.message import EmailMessage

# See https://github.com/redacted/XKCD-password-generator
from xkcdpass import xkcd_password as xp

########################################################################

def setup_cli():
    parser = argparse.ArgumentParser(description='Reset Ruckus WLAN password')

    # Ruckus-related CLI args
    parser.add_argument('--ruckus-ip',
                        required=True,
                        help='Ruckus appliance IP address')
    parser.add_argument('--ruckus-username',
                        required=True,
                        help='Ruckus username')
    parser.add_argument('--ruckus-password',
                        required=True,
                        help='Ruckus password')
    parser.add_argument('--ruckus-zone',
                        required=True,
                        help='Ruckus WLAN zone name')
    parser.add_argument('--ruckus-wlan',
                        required=True,
                        help='Ruckus WLAN name')
    # We can compute this one if not provided
    parser.add_argument('--ruckus-api-base',
                        help='Base Ruckus API URL')

    # SMTP-related CLI args
    parser.add_argument('--smtp-server',
                        required=True,
                        help='SMTP server name')
    parser.add_argument('--smtp-local-hostname',
                        required=True,
                        help='SMTP local server name (for SMTP EHLO)')
    parser.add_argument('--smtp-port',
                        default=25,
                        help='Port number to use to connect to the SMTP server')
    parser.add_argument('--smtp-from',
                        required=True,
                        help='Address to send the email from')
    parser.add_argument('--smtp-to',
                        required=True,
                        help='Address to send the email to')
    parser.add_argument('--smtp-subject',
                        default='WiFi password update',
                        help='Subject line for the email')

    # Miscellaneous CLI args
    parser.add_argument('--debug',
                        default=False,
                        action='store_true',
                        help='Enable debugging output')

    args = parser.parse_args()

    setup_logging(args)

    if args.ruckus_api_base is None:
        # Per Ruckus docs
        args.ruckus_api_base = f'https://{args.ruckus_ip}:8443/wsg/api/public'

    return args

#-----------------------------------------------------------------------

def setup_logging(args):
    # Disable insecure SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    level = logging.INFO
    if args.debug:
        level = logging.DEBUG

    format = '%(asctime)s %(levelname)-5s %(message)s'
    logging.basicConfig(level=level, format=format)

#-----------------------------------------------------------------------

# Login
def ruckus_login(session, args):
    endpoint = '/v13_0/session'
    url      = f'{args.ruckus_api_base}{endpoint}'

    data = {
        'username'          : args.ruckus_username,
        'password'          : args.ruckus_password,
        'timeZoneUtcOffset' : '+00:00',
    }

    logging.info("Logging in to Ruckus...")
    r = session.post(url, json=data, verify=False)

    logging.debug("Ruckus login API result")
    logging.debug(r.text)

    if r.status_code < 200 or r.status_code >= 300:
        logging.error("Failed to login to Ruckus")
        logging.error("Aborting in despair")
        exit(1)

#-----------------------------------------------------------------------

# Find the target Ruckus zone ID
def ruckus_find_zone_entry(session, args):
    endpoint = "/v13_0/rkszones"
    url      = f'{args.ruckus_api_base}{endpoint}'

    logging.info(f'Looking for Ruckus zone ID for "{args.ruckus_zone}"...')
    r     = session.get(url, verify=False)
    zones = r.json()

    logging.debug("Ruckus get zones API result:")
    logging.debug(pformat(zones))

    for zone_entry in zones['list']:
        if zone_entry['name'] == args.ruckus_zone:
            logging.debug(f'Found for Ruckus zone ID for "{args.ruckus_zone}": {zone_entry["id"]}')
            return zone_entry

    logging.error(f'Could not find Ruckus zone ID for "{args.ruckus_zone}"')
    logging.error("Aborting in despair")
    exit(1)

#-----------------------------------------------------------------------

# Find the target Ruckus WLAN ID
def ruckus_find_wlan_entry(session, zone_entry, args):
    zone_id  = zone_entry['id']
    endpoint = f'/v13_0/rkszones/{zone_id}/wlans'
    url      = f'{args.ruckus_api_base}{endpoint}'

    logging.info(f'Looking for Ruckus WLAN ID for "{args.ruckus_wlan}"...')
    r     = session.get(url, verify=False)
    wlans = r.json()

    for wlan_entry in wlans['list']:
        if wlan_entry['name'] == args.ruckus_wlan:
            logging.debug(f'Found for Ruckus WLAN ID for "{args.ruckus_wlan}": {wlan_entry["id"]}')
            return wlan_entry

    logging.error(f'Could not find Ruckis WLAN ID for "{args.ruckus_wlan}"')
    logging.error("Aborting in despair")
    exit(1)

#-----------------------------------------------------------------------

# Query the target WLAN
def ruckus_query_wlan(session, zone_entry, wlan_entry, args):
    zone_id   = zone_entry['id']
    wlan_id   = wlan_entry['id']
    wlan_name = wlan_entry['name']
    endpoint  = f'/v13_0/rkszones/{zone_id}/wlans/{wlan_id}'
    url       = f'{args.ruckus_api_base}{endpoint}'

    logging.info(f'Querying Ruckus WLAN "{wlan_name}" (ID: {wlan_id})')
    r = session.get(url, verify=False)

    wlan = r.json()
    logging.debug("Ruckus WLAN query API result:")
    logging.debug(pformat(wlan))

    return wlan

#-----------------------------------------------------------------------

# Generate a new password
def generate_password(args):
    sources  = string.ascii_letters + string.digits + string.punctuation
    wordfile = xp.locate_wordfile()
    mywords  = xp.generate_wordlist(wordfile=wordfile, min_length=4, max_length=8)
    password = xp.generate_xkcdpassword(mywords, acrostic="shs")
    password = password.title().replace(' ', '')

    logging.debug(f"New password: {password}")
    return password

#-----------------------------------------------------------------------

# Patch the Ruckus WLAN to change the password
def ruckus_patch_wlan_passphrase(session, zone_entry, wlan_entry, wlan, password):
    zone_id   = zone_entry['id']
    wlan_id   = wlan_entry['id']
    wlan_name = wlan_entry['name']
    endpoint  = f'/v13_0/rkszones/{zone_id}/wlans/{wlan_id}'
    url       = f'{args.ruckus_api_base}{endpoint}'

    # Per Ruckus docs:
    #
    # - "passphrase": This only applies to WPA2 and WPA mixed mode
    # - "saePassphrase": This only applies to WPA3 and WPA23 mixed mode
    #
    # Probably need some logic here to choose between 'passphrase' and
    # 'saePassphrase', depending on the wlan['mode'] value
    mode = wlan['mode']
    if mode in [ "WPA2", "WPA_Mixed" ]:
        key = 'passphrase'
    elif mode in [ "WPA3", "WPA23_Mixed" ]:
        key = 'saePassphrase'
    else:
        logging.error(f"Unrecognized Ruckus WLAN encryption mode: {mode}")
        logging.error("This script only recognizes: WPA2, WPA_Mixed, WPA3, WPA23_Mixed")
        logging.error(f"Don't know how to change {mode} passwords")
        exit(1)

    patch = {
        'encryption' : {
            "method" : wlan['encryption']['method'],
            key      : password,
        },
    }

    logging.info(f'Changing Ruckus WLAN "{wlan_name}" (ID: {wlan_id}) password...')
    r = session.patch(url, verify=False, data=json.dumps(patch))
    logging.debug("Ruckus login API result")
    logging.debug(r.text)

#-----------------------------------------------------------------------

def send_email(args, password):
    email_body = f'''<p>The WiFi password for the "{args.ruckus_wlan}" network has been changed to:</p>

<p>{password}</p>

<p>Your friendly daemon,<br />
Howard</p>'''

    with smtplib.SMTP(host=args.smtp_server,
                      local_hostname=args.smtp_local_hostname,
                      port=args.smtp_port) as smtp:
        if args.debug:
            smtp.set_debuglevel(2)

        msg = EmailMessage()
        msg.set_content(email_body)
        msg['Subject'] = args.smtp_subject
        msg['From']    = args.smtp_from,
        msg['To']      = args.smtp_to,
        msg.replace_header('Content-Type', 'text/html')

        logging.info(f"Sending email to {args.smtp_to}...")
        smtp.send_message(msg)

#-----------------------------------------------------------------------

# Logout
def ruckus_logout(session, args):
    endpoint = '/v13_0/session'
    url      = f'{args.ruckus_api_base}{endpoint}'

    logging.info("Logging out of Ruckus API...")
    session.delete(url, verify=False)
    logging.debug("Ruckus logout API result:")
    logging.debug(r.text)

#-----------------------------------------------------------------------

def main():
    args = setup_cli()

    # Setup a persistent session for Ruckus API calls
    session = requests.Session()
    session.headers.update({'Content-Type': 'application/json'})

    try:
        # Login to the Ruckus API
        ruckus_login(session, args)

        # Find all the relevant entities using Ruckus API calls
        zone_entry = ruckus_find_zone_entry(session, args)
        wlan_entry = ruckus_find_wlan_entry(session, zone_entry, args)
        wlan       = ruckus_query_wlan(session, zone_entry, wlan_entry, args)

        # Generate a new password, reset the target Ruckus WLAN to it, and
        # send an email with the new password
        password   = generate_password(args)
        ruckus_patch_wlan_passphrase(session, zone_entry, wlan_entry, wlan, password)
        send_email(args, password)

        # Logout of the Ruckus API
        ruckus_logout(session, args)
    except KeyboardInterrupt as e:
        logging.error("User interrupted -- aborted")
        exit(1)
    except Exception as e:
        logging.error(e)
        exit(1)

#-----------------------------------------------------------------------

if __name__ == "__main__":
    main()
