#!/usr/bin/env python

""" 
    Implementation of the custom Splunk> search command "haveibeenpwned" used for querying haveibeenpwned.com for leaks affecting provided mail adresses or domains.
    
    Author: Harun Kuessner
    Version: 1.1.0
    License: http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import
from __future__ import print_function
from time       import sleep

import datetime
import json
import sys

import splunklib.six.moves.http_client as http_client
import splunklib.client as client
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

@Configuration()
class hibpCommand(StreamingCommand):
    """ 
    ##Syntax

    haveibeenpwned [mode=mail|domain] [threshold=<days>] <field-list>

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
        **Description:** query for mail address or domain breach''',
        require=False, default="mail")

    threshold = Option(
        doc='''
        **Syntax:** **threshold=***<days>*
        **Description:** How many days to look back in time for breaches''',
        require=False, default=7)

    def stream(self, events):
        # Initialize variables and HTTP(S) connection
        tracker     = 0
        date        = datetime.datetime.now()
        use_proxies = 0
        api_key     = None

        service     = client.Service(token=self.metadata.searchinfo.session_key)
        use_proxies = service.confs["haveibeenpwned"]["settings"]["use_proxies"]
        api_key     = service.confs["haveibeenpwned"]["settings"]["api_key"]
        #api_key     = service.storage_passwords.list(count=-1, search="haveibeenpwned")[0].clear_password
        
        if api_key is not None and len(api_key) > 0:
            headers = {'user-agent': 'splunk-app-for-hibp/1.1.0', 'hibp-api-key': '{0}'.format(api_key)}
        else:
            headers = {'user-agent': 'splunk-app-for-hibp/1.1.0'}
            self.logger.warning("No valid haveibeenpwneed.com API key was provided via app's setup screen. mode=mail will not work.")

        if use_proxies == 1:
            https_proxy = service.confs["haveibeenpwned"]["settings"]["https_proxy"]
            http_proxy  = service.confs["haveibeenpwned"]["settings"]["http_proxy"]

            try:
                connection = http_client.HTTPSConnection('{0}'.format(https_proxy))
                connection.set_tunnel('haveibeenpwned.com')
            except Exception as e1:
                self.logger.error("HTTPS proxy connection failed, falling back to HTTP: {0}".format(e))
                connection.close()
                try:
                    connection = http_client.HTTPConnection('{0}'.format(http_proxy))
                    connection.set_tunnel('haveibeenpwned.com')
                except Exception as e2:
                    self.logger.error("HTTP proxy connection failed, falling back to direct HTTPS connection: {0}".format(e))
                    connection.close()
                    try:
                        connection = http_client.HTTPSConnection('haveibeenpwned.com', 443)
                    except Exception as e3:
                        self.logger.error("Direct HTTPs connection failed, returning: {0}".format(e))
                        connection.close()
                        return
        else:
            try:
                connection = http_client.HTTPSConnection('haveibeenpwned.com', 443)
            except Exception as e:
                self.logger.error("Direct HTTPs connection failed, returning: {0}".format(e))
                connection.close()
                return

        for event in events:
            if self.mode == "domain":
                # Check for domain breaches    
                breach = []

                if tracker == 0:
                    try:
                        connection.request("GET", '/api/v3/breaches', headers=headers)
                        response = connection.getresponse()
                    except Exception as e:
                        self.logger.error("HTTP request failed: {0}".format(e))
                        return

                    if response.status == 200:
                        data = response.read()
                    if response.status == 429:
                        sleep(5)
                        try:
                            connection.request("GET", '/api/v3/breaches', headers=headers)
                            response = connection.getresponse()
                        except Exception as e:
                            self.logger.error("HTTP request failed: {0}".format(e))
                            return
                        
                    tracker = 1

                if data is not None:
                    for entry in json.loads(data.decode('utf8')):
                        if int((date - datetime.datetime.strptime(entry['AddedDate'], '%Y-%m-%dT%H:%M:%SZ')).days) > int(self.threshold) or not event[self.fieldnames[0]] in entry['Domain']:
                            pass
                        else:
                            dataclass = []
                            for dataclasses in entry['DataClasses']:
                                dataclass.append(dataclasses.encode('utf-8'))

                            breach.append(['Title: {0}'.format(entry['Title']), \
                                           'Domain: {0}'.format(entry['Domain']), \
                                           'Date of Breach: {0}'.format(entry['BreachDate']), \
                                           'Date of Availability: {0}'.format(entry['AddedDate']), \
                                           'Breached Accounts: {0}'.format(entry['PwnCount']), \
                                           'Breach Description: {0}'.format(entry['Description']), \
                                           'Breached Data: {0}'.format(dataclass)])

                    if len(breach) == 0:
                        event['breach'] = "No breach reported for given domain and time frame."
                    else:
                        event['breach'] = ""
                        for entry in breach:
                            for item in entry:
                                event['breach'] += str(item) + "\r\n"
                            event['breach'] += "\r\n"

            else:
                # Check for account breaches
                breach = []

                try:
                    connection.request("GET", '/api/v3/breachedaccount/{0}?truncateResponse=false'.format(event[self.fieldnames[0]]), headers=headers)
                    response = connection.getresponse()
                except Exception as e:
                    self.logger.error("HTTP request failed: {0}".format(e))
                    return

                sleep(1.7)

                if response.status == 200:
                    data = response.read()

                    for entry in json.loads(data.decode('utf8')):
                        if int((date - datetime.datetime.strptime(entry['AddedDate'], '%Y-%m-%dT%H:%M:%SZ')).days) > int(self.threshold):
                            pass
                        else:
                            dataclass = []
                            for dataclasses in entry['DataClasses']:
                                dataclass.append(dataclasses.encode('utf-8'))

                            breach.append(['Title: {0}'.format(entry['Title']), \
                                           'Domain: {0}'.format(entry['Domain']), \
                                           'Date of Breach: {0}'.format(entry['BreachDate']), \
                                           'Date of Availability: {0}'.format(entry['AddedDate']), \
                                           'Breached Data: {0}'.format(dataclass)])

                    if len(breach) == 0: 
                        event['breach'] = "No breach reported for given account and time frame."
                    else:
                        event['breach'] = ""
                        for entry in breach:
                            for item in entry:
                                event['breach'] += str(item) + "\r\n"
                            event['breach'] += "\r\n"

                elif response.status == 429:
                    sleep(5)
                elif response.status == 404:
                    event['breach'] = "No breach reported for given account and time frame."
                else:
                    pass
    
                # Check for account pastes
                paste = []
    
                try:
                    connection.request("GET", '/api/v2/pasteaccount/{0}'.format(event[self.fieldnames[0]]), headers=headers)
                    response = connection.getresponse()
                except Exception as e:
                    self.logger.error("HTTP request failed: {0}".format(e))
                    return

                sleep(1.7)

                if response.status == 200:
                    data = response.read()

                    for entry in json.loads(data.decode('utf8')):
                        if int((date - datetime.datetime.strptime(entry['Date'], '%Y-%m-%dT%H:%M:%SZ')).days) > int(self.threshold):
                            pass
                        else:
                            paste.append(['Title: {0}'.format(entry['Title']), \
                                          'Source: {0}'.format(['Source']), \
                                          'Paste ID: {0}'.format(entry['Id'])])

                    if len(paste) == 0:
                        event['paste'] = "No paste reported for given account and time frame."
                    else:
                        event['paste'] = ""
                        for entry in paste:
                            for item in entry:
                                event['paste'] += str(item) + "\r\n"
                            event['paste'] += "\r\n"

                elif response.status == 429:
                    sleep(5)
                elif response.status == 404:
                    event['paste'] = "No paste reported for given account and time frame."
                else:
                    pass

            connection.close()
            yield event

dispatch(hibpCommand, sys.argv, sys.stdin, sys.stdout, __name__)