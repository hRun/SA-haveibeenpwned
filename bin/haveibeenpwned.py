#!/usr/bin/env python

"""
    Implementation of the custom Splunk> search command "haveibeenpwned" used for querying haveibeenpwned.com for leaks affecting provided mail adresses or domains.

    Author: Harun Kuessner
    Version: 1.2.2
    License: http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import
from __future__ import print_function
from os         import environ
from os.path    import join
from time       import sleep

import datetime
import logging
import json
import sys

import splunklib.client                as client
import splunklib.six.moves.http_client as http_client

from splunklib.six.moves.urllib import parse as url_parse
from splunklib.searchcommands   import dispatch, StreamingCommand, Configuration, Option, validators

@Configuration()
class hibpCommand(StreamingCommand):
    """
    ##Syntax

    haveibeenpwned [mode=mail|domain] [threshold=<days>] [pastes=all|dated|none] <field-list>

    ##Description

    Query haveibeenpwned.com for leaks affecting your assets.

    ##Requirements

    Install on search head. Usage of mode=mail requires a valid API key to be provided via the app's setup screen.

    ##Examples

    search sourcetype="logs" | table _time, email | haveibeenpwned mode=mail email

    """

    mode = Option(
        doc='''
        **Syntax:** **mode=***mail|domain*
        **Description:** Whether to query for mail address or domain breach''',
        require=False, default="mail")

    threshold = Option(
        doc='''
        **Syntax:** **threshold=***<days>*
        **Description:** How many days to look back in time for breaches''',
        require=False, default=7)

    pastes = Option(
        doc='''
        **Syntax:** **pastes=***all|dated|none*
        **Description:** Whether to query for account pastes or not or only those with a timestamp when using mode=mail''',
        require=False, default="dated")

    def stream(self, events):
        # Stop execution on invalid option values
        if not self.mode in ['domain', 'mail']:
            raise RuntimeWarning('Invalid value for option "mode" specified: "{0}"'.format(self.mode))
        if self.mode == 'mail' and not self.pastes in ['all', 'dated', 'none']:
            raise RuntimeWarning('Invalid value for option "pastes" specified: "{0}"'.format(self.pastes))
        try:
            int(self.threshold)
        except:
            raise RuntimeWarning('Invalid value for option "threshold" specified: "{0}"'.format(self.threshold))

        # Set up logging
        logger  = logging.getLogger('haveibeenpwned')
        handler = logging.handlers.RotatingFileHandler(join(environ['SPLUNK_HOME'], 'var', 'log', 'splunk', 'sa_haveibeenpwned.log'), maxBytes=1048576, backupCount=2)
        handler.setFormatter(logging.Formatter("%(asctime)-15s %(levelname)-5s %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        # Initialize variables and HTTPS connection
        tracker     = 0
        date        = datetime.datetime.now()
        use_proxies = 0
        api_key     = None

        service     = client.Service(token=self.metadata.searchinfo.session_key)
        use_proxies = int(service.confs["sa_haveibeenpwned_settings"]["proxy"]["use_proxies"])
        storage_passwords   = service.storage_passwords
        for storage_password in storage_passwords:
            if storage_password.realm == "__REST_CREDENTIAL__#SA-haveibeenpwned#configs/conf-sa_haveibeenpwned_settings" and storage_password.username == "additional_parameters``splunk_cred_sep``1":
                api_key = json.loads(storage_password.clear_password)['api_key']

        if api_key is not None and len(api_key) > 0:
            headers = {'user-agent': 'splunk-app-for-hibp/1.2.0', 'hibp-api-key': '{0}'.format(api_key)}
        else:
            headers = {'user-agent': 'splunk-app-for-hibp/1.2.0'}
            logger.info("No valid haveibeenpwneed.com API key was provided via app's setup screen. mode=mail will not work.")

        if use_proxies == 1:
            https_proxy = service.confs["sa_haveibeenpwned_settings"]["proxy"]["https_proxy"].split('//')[-1].rstrip('/')
            http_proxy  = service.confs["sa_haveibeenpwned_settings"]["proxy"]["http_proxy"].split('//')[-1].rstrip('/')

            try:
                connection = http_client.HTTPSConnection('{0}'.format(https_proxy))
                connection.set_tunnel('haveibeenpwned.com')
            except Exception as e1:
                connection.close()
                logger.error("HTTPS proxy connection failed, falling back to HTTP proxy: {0}".format(e1))
                try:
                    connection = http_client.HTTPConnection('{0}'.format(http_proxy))
                    connection.set_tunnel('haveibeenpwned.com')
                except Exception as e2:
                    connection.close()
                    logger.error("HTTP proxy connection failed, falling back to direct HTTPS connection: {0}".format(e2))
                    raise RuntimeWarning("Proxy connection attempts failed: {}, {}".format(e1, e2))

        for event in events:
            # Check for domain breaches
            if self.mode == "domain":
                breach = []

                # Always do a single request for all breaches only, independent of how many domains to check for
                if tracker == 0:
                    try:
                        if not use_proxies == 1:
                            connection = http_client.HTTPSConnection('haveibeenpwned.com', 443)
                        connection.request("GET", '/api/v3/breaches', headers=headers)
                        response = connection.getresponse()
                    except Exception as e:
                        connection.close()
                        logger.error("HTTPS request failed: {0}".format(e))
                        raise RuntimeWarning("HTTPS request failed: {0}".format(e))

                    if response.status == 200:
                        data = response.read()

                    # Wait and attempt one more time if we exceeded the rate limit
                    if response.status == 429:
                        sleep(3.2)
                        try:
                            if not use_proxies == 1:
                                connection = http_client.HTTPSConnection('haveibeenpwned.com', 443)
                            connection.request("GET", '/api/v3/breaches', headers=headers)
                            response = connection.getresponse()
                            if response.status == 200:
                                data = response.read()
                            else:
                                raise Exception
                        except Exception as e:
                            connection.close()
                            logger.error("HTTPS request failed: {0}".format(e))
                            raise RuntimeWarning("HTTPS request failed: {0}".format(e))

                    tracker = 1
                    connection.close()

                if data is not None:
                    for entry in json.loads(data.decode('utf8')):
                        if int((date - datetime.datetime.strptime(entry['AddedDate'], '%Y-%m-%dT%H:%M:%SZ')).days) > int(self.threshold) or not event[self.fieldnames[0]] in entry['Domain']:
                            pass
                        else:
                            dataclass = []
                            for dataclasses in entry['DataClasses']:
                                dataclass.append(dataclasses)

                            breach.append(['Title: {0}'.format(entry['Title']), \
                                           'Domain: {0}'.format(entry['Domain']), \
                                           'Date of Breach: {0}'.format(entry['BreachDate']), \
                                           'Date of Availability: {0}'.format(entry['AddedDate']), \
                                           'Breached Accounts: {0}'.format(entry['PwnCount']), \
                                           'Breached Data: {0}'.format(', '.join(dataclass)), \
                                           'Breach Description: {0}'.format(entry['Description'])])

                    if len(breach) == 0:
                        event['breach'] = "No breach reported for given domain and time frame."
                    else:
                        event['breach'] = ""
                        for entry in breach:
                            for item in entry:
                                event['breach'] += str(item) + "\r\n"
                            event['breach'] += "\r\n"

            # Check for account breaches and pastes
            elif self.mode == "mail":
                breach = []
                paste  = []

                # Only proceed if an API key was set up
                if api_key is None or len(api_key) < 1:
                    raise RuntimeWarning("Usage of mode=mail requires a valid haveibeenpwneed.com API key to be provided via the app's setup screen.")

                # Check for account breaches
                try:
                    if not use_proxies == 1:
                        connection = http_client.HTTPSConnection('haveibeenpwned.com', 443)
                    connection.request("GET", '/api/v3/breachedaccount/{0}?truncateResponse=false'.format(url_parse.quote_plus(event[self.fieldnames[0]])), headers=headers)
                    response = connection.getresponse()
                except Exception as e:
                    connection.close()
                    logger.error("HTTPS request failed: {0}".format(e))
                    return # Return, don't throw an error, as that would cancel the search for all other events

                if response.status == 200:
                    data = response.read()

                    for entry in json.loads(data.decode('utf8')):
                        if int((date - datetime.datetime.strptime(entry['AddedDate'], '%Y-%m-%dT%H:%M:%SZ')).days) > int(self.threshold):
                            pass
                        else:
                            dataclass = []
                            for dataclasses in entry['DataClasses']:
                                dataclass.append(dataclasses)

                            breach.append(['Title: {0}'.format(entry['Title']), \
                                           'Domain: {0}'.format(entry['Domain']), \
                                           'Date of Breach: {0}'.format(entry['BreachDate']), \
                                           'Date of Availability: {0}'.format(entry['AddedDate']), \
                                           'Breached Data: {0}'.format(', '.join(dataclass))])

                    if len(breach) == 0:
                        event['breach'] = "No breach reported for given account and time frame."
                    else:
                        event['breach'] = ""
                        for entry in breach:
                            for item in entry:
                                event['breach'] += str(item) + "\r\n"
                            event['breach'] += "\r\n"

                elif response.status == 429:
                    sleep(3.2)
                elif response.status == 404:
                    event['breach'] = "No breach reported for given account and time frame."
                else:
                    pass

                if not use_proxies == 1:
                    connection.close()
                sleep(1.7) # Wait before next request to not exceed rate limit

                # Check for account pastes
                if self.pastes in ['all', 'dated']:
                    try:
                        if not use_proxies == 1:
                            connection = http_client.HTTPSConnection('haveibeenpwned.com', 443)
                        connection.request("GET", '/api/v3/pasteaccount/{0}'.format(url_parse.quote_plus(event[self.fieldnames[0]])), headers=headers)
                        response = connection.getresponse()
                    except Exception as e:
                        connection.close()
                        logger.error("HTTPS request failed: {0}".format(e))
                        return # Return, don't throw an error, as that would cancel the search for all other events

                    if response.status == 200:
                        data = response.read()

                        for entry in json.loads(data.decode('utf8')):
                            try: # Handle pastes without title
                                str(entry['Title'])
                            except:
                                entry['Title'] = "N/A"

                            if self.pastes == 'all' and not entry['Date']: # Handle pastes without timestamp
                                entry['Date'] = "N/A"

                            if entry['Date'] and (entry['Date'] == "N/A" or int((date - datetime.datetime.strptime(entry['Date'], '%Y-%m-%dT%H:%M:%SZ')).days) <= int(self.threshold)):
                                paste.append(['Title: {0}'.format(entry['Title']), \
                                              'Source: {0}'.format(entry['Source']), \
                                              'Paste ID: {0}'.format(entry['Id']), \
                                              'Date: {0}'.format(entry['Date'])])
                            else:
                                pass

                        if len(paste) == 0:
                            event['paste'] = "No paste reported for given account and time frame."
                        else:
                            event['paste'] = ""
                            for entry in paste:
                                for item in entry:
                                    event['paste'] += str(item) + "\r\n"
                                event['paste'] += "\r\n"

                    elif response.status == 429:
                        sleep(3.2)
                    elif response.status == 404:
                        event['paste'] = "No paste reported for given account and time frame."
                    else:
                        pass

                    if not use_proxies == 1:
                        connection.close()
                    sleep(1.7) # Wait before next request to not exceed rate limit

            yield event

        if use_proxies == 1:
            connection.close()

dispatch(hibpCommand, sys.argv, sys.stdin, sys.stdout, __name__)
