#!/usr/bin/env python

""" 
    Implementation of the custom Splunk> search command "haveibeenpwned" used for \
    querying haveibeenpwned.com for leaks affecting provided mail adresses or domains.
    
    Author: Harun Kuessner
    Version: 1.0
"""

import base64
import datetime
import json
import re
import requests
import sys
import logging, logging.handlers, logging.config

from time import sleep

import splunklib.client as client
from   splunklib.searchcommands import \
       dispatch, StreamingCommand, Configuration, Option, validators

@Configuration()
class hibpCommand(StreamingCommand):
    """ 
    ##Syntax

    haveibeenpwned [mode=mail|domain] [threshold=<days>] <field-list>

    ##Description
    
    Query haveibeenpwned.com for leaks affecting your assets.

    ##Requirements

    Install on search head.

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
        **Description:** How many days to look back in tome for breaches''',
        require=False, default=7)

    def stream(self, events):

	# Set up logging
        logger  = logging.getLogger('haveibeenpwned')
	handler = logging.handlers.RotatingFileHandler('/opt/splunk/var/log/splunk/send_alert_haveibeenpwned.log', \
	                                               maxBytes=10000000, backupCount=1)
	handler.setFormatter(logging.Formatter("%(asctime)-15s %(levelname)-5s %(message)s"))
	logger.addHandler(handler)
	logger.setLevel(logging.DEBUG)
	
	logger.info("Starting to query haveibeenpwned API.")

	# Bind to current Splunk session
	sessionKey = self.metadata.searchinfo.session_key
	tracker    = 0
	date       = datetime.datetime.now()
	
	for event in events:
		if self.mode == "domain":
			# Check for domain breaches	
			url    = 'https://haveibeenpwned.com/api/v2/breaches'
			breach = []

			if tracker == 0:
                                try:
				        response = requests.get(url)
                                except Exception as e:
                                        logger.error("HTTP request failed: {0}".format(e))
                                        return

				tracker  = 1

				if response.status_code == 200:
					data = response.json()
                                if response.status_code == 429:
                                        sleep(5)
				else:
					data = 0

			if data != 0:
				for entry in data:
                                        if int((date - datetime.datetime.strptime(entry['AddedDate'], '%Y-%m-%dT%H:%M:%SZ')).days) > int(self.threshold) \
                                           or not event[self.fieldnames[0]] in entry['Domain']:
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
                                        event['breach'] = "No Breach"
                                else:
                                        event['breach'] = ""
                                        for entry in breach:
                                                for item in entry:
					                event['breach'] += str(item) + "\r\n"
                                                event['breach'] += "\r\n"

		else:
			# Check for account breaches
			url       = 'https://haveibeenpwned.com/api/v2/breachedaccount/%s' % event[self.fieldnames[0]]
			breach    = []

                        try:
                                response  = requests.get(url)
                        except Exception as e:
                                logger.error("HTTP request failed: {0}".format(e))
                                return

			sleep(1.7)

                        if response.status_code == 200:
				data = response.json()

				for entry in data:
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
					event['breach'] = "No Breach"
				else:
                                        event['breach'] = ""
                                        for entry in breach:
                                                for item in entry:
                                                        event['breach'] += str(item) + "\r\n"
                                                event['breach'] += "\r\n"

                        elif response.status_code == 429:
                                sleep(5)
			elif response.status_code == 404:
				event['breach'] = "No Breach"
                        else:
                                pass

			# Check for account pastes
                        url      = 'https://haveibeenpwned.com/api/v2/pasteaccount/%s' % event[self.fieldnames[0]]
			paste    = []

                        try:
                                response = requests.get(url)
                        except Exception as e:
                                logger.error("HTTP request failed: {0}".format(e))
                                return

			sleep(1.7)

                        if response.status_code == 200:
                                data = response.json()

                                for entry in data:
                                        if int((date - datetime.datetime.strptime(entry['Date'], '%Y-%m-%dT%H:%M:%SZ')).days) > int(self.threshold):
                                                pass
                                        else:
                                                paste.append(['Title: {0}'.format(entry['Title']), \
                                                              'Source: {0}'.format(['Source']), \
                                                              'Paste ID: {0}'.format(entry['Id'])])

                                if len(paste) == 0:
                                        event['paste'] = "No Paste"
                                else:
                                        event['paste'] = ""
                                        for entry in paste:
                                                for item in entry:
                                                        event['paste'] += str(item) + "\r\n"
                                                event['paste'] += "\r\n"

                        elif response.status_code == 429:
                                sleep(5)
                        elif response.status_code == 404:
                                event['paste'] = "No Paste"
                        else:
                                pass

		yield event

dispatch(hibpCommand, sys.argv, sys.stdin, sys.stdout, __name__)
