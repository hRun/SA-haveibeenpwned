# SA-haveibeenpwned

A Splunk® add-on providing a custom search command _haveibeenpwned_ to query Troy Hunt's haveibeenpwned API (https://haveibeenpwned.com/api/v3/) for known breaches of your (company's) domains or your friends'/family's/enemies'/hardly distantly related someone's/employees'/colleagues' mail adresses.

Please respect people's privacy and adhere to the service's acceptable use (https://haveibeenpwned.com/API/v3#AcceptableUse). I tried respecting the limits posed on the API's use in the command's source code, which is why you'll have to have a little patience when querying for large amounts of mail addresses.

I was unsatisfied with the publicly available Splunk add-ons already providing this functionality as they either didn't allow control over what and how is queried for or didn't format the output to my wishes. So I came up with my own Splunk add-on implementing these missing features.

Cross-compatible with Python 2 and 3. Tested on Splunk Enterprise 7.3.5 and 8.0.2.1.

Licensed under http://www.apache.org/licenses/LICENSE-2.0.

## Installation

Just unpack to _$SPLUNK_HOME/etc/apps_ on your Splunk search head and restart the instance. Use the deployer in a distributed environment.

Set _python.version=python2_ or _python.version=python3_ in _commands.conf_ if you would like to explicitly specify the Python version to use. Otherwise this will be determined by your instance's global settings.

## Requirements

Your Splunk instance requires acess to the internet (via a proxy) to query https://haveibeenpwned.com/api/v3/*.

Unfortunately parts of the HIBP API now require an API key which you can obtain here: https://haveibeenpwned.com/API/Key. Specify your API key via the app's setup screen to be able to use _mode=mail_. _mode=domain_ will work without an API key.

## Usage

Use as a search command like so:

_search index=example | table email | haveibeenpwned [mode=<mail|domain>] [threshold=\<days>] \<field-list>_

_mode_: Control whether to query for breaches regarding one or multiple domains or specific mail addresses. Default: mail.

_threshold_: Set how many days to look back for breaches. Default: 7 days.

Expect the search to take ~ 2 seconds per mail address when using mode=mail due to the API's acceptable use. Do not attempt to spam the search as it will only degrade the performance further. 

## History

### v1.2.1

* Better connection state handling and URL encoding

* Updated to Splunklib 1.6.14

### v1.2.0

* Overall enhancements and bug fixes

* Implemented better sanity checks and error handling

## TODO / Known Issues

* Potentially add a mode to query the passwords API. As password hashes should not be stored in Splunk this should not be a valid use case.
