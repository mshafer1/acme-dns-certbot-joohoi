#!/usr/bin/env python3
import json
import os
import requests
import sys

__license__ = """
MIT License

Copyright (c) 2018 Joona Hoikkala

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

### EDIT THESE: Configuration values ###

# URL to acme-dns instance
ACMEDNS_URL = "https://auth.acme-dns.io"
# Path for acme-dns credential storage
STORAGE_PATH = "/etc/letsencrypt/acmedns.json"
# Whitelist for address ranges to allow the updates from
# Example: ALLOW_FROM = ["192.168.10.0/24", "::1/128"]
ALLOW_FROM = []
# Force re-registration. Overwrites the already existing acme-dns accounts.
FORCE_REGISTER = False

# Optional, mTLS region
# NOTE: ACMDEDNS_URL must have SSL enabled (https://) for this to have an effect
USE_MTLS = False # change to True to present client certificate
MTLS_CERT_PATH = "/etc/letsencrypt/acmedns_mtls_client_cert.pem"
MTLS_KEY_PATH = "/etc/letsencrypt/acmedns_mtls_client_key.pem"

###   DO NOT EDIT BELOW THIS POINT   ###
###         HERE BE DRAGONS          ###

DOMAIN = os.environ["CERTBOT_DOMAIN"]
if DOMAIN.startswith("*."):
    DOMAIN = DOMAIN[2:]
VALIDATION_DOMAIN = "_acme-challenge."+DOMAIN
VALIDATION_TOKEN = os.environ["CERTBOT_VALIDATION"]


class AcmeDnsClient(object):
    """
    Handles the communication with ACME-DNS API
    """

    def __init__(self, acmedns_url):
        self.acmedns_url = acmedns_url

    def register_account(self, allowfrom):
        """Registers a new ACME-DNS account"""

        mtls_args = {}
        if USE_MTLS:
            mtls_args['cert'] = (MTLS_CERT_PATH, MTLS_KEY_PATH)

        if allowfrom:
            # Include whitelisted networks to the registration call
            reg_data = {"allowfrom": allowfrom}
            res = requests.post(self.acmedns_url+"/register",
                                data=json.dumps(reg_data),
                                **mtls_args)
        else:
            res = requests.post(self.acmedns_url+"/register", **mtls_args)
        if res.status_code == 201:
            # The request was successful
            return res.json()
        else:
            # Encountered an error
            msg = ("Encountered an error while trying to register a new acme-dns "
                   "account. HTTP status {}, Response body: {}")
            print(msg.format(res.status_code, res.text))
            sys.exit(1)

    def update_txt_record(self, account, txt):
        """Updates the TXT challenge record to ACME-DNS subdomain."""
        update = {"subdomain": account['subdomain'], "txt": txt}
        headers = {"X-Api-User": account['username'],
                   "X-Api-Key": account['password'],
                   "Content-Type": "application/json"}
        mtls_args = {}
        if USE_MTLS:
            mtls_args['cert'] = (MTLS_CERT_PATH, MTLS_KEY_PATH)
        res = requests.post(self.acmedns_url+"/update",
                            headers=headers,
                            data=json.dumps(update),
                            **mtls_args)
        if res.status_code == 200:
            # Successful update
            return
        else:
            msg = ("Encountered an error while trying to update TXT record in "
                   "acme-dns. \n"
                   "------- Request headers:\n{}\n"
                   "------- Request body:\n{}\n"
                   "------- Response HTTP status: {}\n"
                   "------- Response body: {}")
            s_headers = json.dumps(headers, indent=2, sort_keys=True)
            s_update = json.dumps(update, indent=2, sort_keys=True)
            s_body = json.dumps(res.json(), indent=2, sort_keys=True)
            print(msg.format(s_headers, s_update, res.status_code, s_body))
            sys.exit(1)

class Storage(object):
    def __init__(self, storagepath):
        self.storagepath = storagepath
        self._data = self.load()

    def load(self):
        """Reads the storage content from the disk to a dict structure"""
        data = dict()
        filedata = ""
        try:
            with open(self.storagepath, 'r') as fh:
                filedata = fh.read()
        except IOError as e:
            if os.path.isfile(self.storagepath):
                # Only error out if file exists, but cannot be read
                print("ERROR: Storage file exists but cannot be read")
                sys.exit(1)
        try:
            data = json.loads(filedata)
        except ValueError:
            if len(filedata) > 0:
                # Storage file is corrupted
                print("ERROR: Storage JSON is corrupted")
                sys.exit(1)
        return data

    def save(self):
        """Saves the storage content to disk"""
        serialized = json.dumps(self._data)
        try:
            with os.fdopen(os.open(self.storagepath,
                                   os.O_WRONLY | os.O_CREAT, 0o600), 'w') as fh:
                fh.truncate()
                fh.write(serialized)
        except IOError as e:
            print("ERROR: Could not write storage file.")
            sys.exit(1)

    def put(self, key, value):
        """Puts the configuration value to storage and sanitize it"""
        # If wildcard domain, remove the wildcard part as this will use the
        # same validation record name as the base domain
        if key.startswith("*."):
            key = key[2:]
        self._data[key] = value

    def fetch(self, key):
        """Gets configuration value from storage"""
        try:
            return self._data[key]
        except KeyError:
            return None

if __name__ == "__main__":
    # Init
    client = AcmeDnsClient(ACMEDNS_URL)
    storage = Storage(STORAGE_PATH)

    # Check if an account already exists in storage
    account = storage.fetch(DOMAIN)
    if FORCE_REGISTER or not account:
        # Create and save the new account
        account = client.register_account(ALLOW_FROM)
        storage.put(DOMAIN, account)
        storage.save()

        # Display the notification for the user to update the main zone
        msg = "Please add the following CNAME record to your main DNS zone:\n{}"
        cname = "{} CNAME {}.".format(VALIDATION_DOMAIN, account["fulldomain"])
        print(msg.format(cname))

    # Update the TXT record in acme-dns instance
    client.update_txt_record(account, VALIDATION_TOKEN)
