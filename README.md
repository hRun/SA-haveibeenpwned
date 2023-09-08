# SA-haveibeenpwned

A Splunk® add-on providing a custom search command _haveibeenpwned_ to query Troy Hunt's haveibeenpwned API (https://haveibeenpwned.com/api/v3/) for known breaches of your (company's) domains or your friends'/family's/enemies'/hardly distantly related someone's/employees'/colleagues' mail adresses.

Please respect people's privacy and adhere to the service's acceptable use (https://haveibeenpwned.com/API/v3#AcceptableUse). I tried respecting the limits posed on the API's use in the command's source code, which is why you'll have to have a little patience when querying for large amounts of mail addresses.

I was unsatisfied with the publicly available Splunk add-ons already providing this functionality as they either didn't allow control over what and how is queried for or didn't format the output to my wishes. So I came up with my own Splunk add-on implementing these missing features.

Cross-compatible with Python 2 and 3. Tested on Splunk Enterprise 9.1.1 on Windows, Linux and Splunk Cloud.

Licensed under http://www.apache.org/licenses/LICENSE-2.0.

* Authors: Harun Kuessner
* Version: 2.3.0


## Installation & Updating

Just unpack to _$SPLUNK_HOME/etc/apps_ on your Splunk search head and restart the instance. Use the deployer in a distributed environment.

For legacy Splunk environments, if you prefer a slimmer implementation or if Splunk's capability limitations are not an option, please use add-on version 1.2.2. Overall functionality is exactly the same. 

**Important note on updating from version 2.1.0 to 2.2.x:** 

Due to changes in the HIBP API's rate limiting, a parameter to set the supplied API key's individual rate limit was added on the add-on's configuration page. It controls sleep intervals during search execution to prevent provoking API timeouts. The parameter is set to 10 requests per minute by default (current lowest tier). To make full use of your API plan, set it to the rate limit tied to the entered API key (as visible from https://haveibeenpwned.com/API/Key/Verify).



## Requirements & Setup

Your Splunk instance requires acess to the internet (via a proxy) to query https://haveibeenpwned.com/api/v3/. Configure proxies via the app's configuration page if required. Currently only HTTP(S) proxies are supported and only Basic Authentication. Support for SOCKS proxies and NTLM authentication might be added in a later verion of the app.

Unfortunately parts of the HIBP API now require an API key which you can obtain here: https://haveibeenpwned.com/API/Key. Specify your API key via the app's configuration page to be able to use _mode=mail_ and _mode=monitored_. Usage of these modes also requires users to have the _list\_storage\_passwords_ capability. A custom role _can\_query\_hibp_ is supplied to empower users (including all negative implications this capability brings with it until Splunk finally decides to fix it). 

_mode=domain_ will work without further configuration, without an API key and without the _list\_storage\_passwords_ capability.

Set _python.version=python2_ in _commands.conf_ if for some reason you need to use the odler Python version. Set _python.version=python2_ in _restmap.conf_ if you experience issues with the app's configuration page on older Splunk instances.


## Usage

Use as a search command like so:

_search index=example | table email | haveibeenpwned [mode=<mail|domain|monitored>] [threshold=\<days>] [output=<text|json>] [pastes=\<all|dated|none>] \<field-list>_

_mode_: Set whether to query for breaches concerning the domain supplied in _field-list_ (mode=domain), whether to check a list of mail addresses for pwnage (mode=mail), or retrieve all eventually pwned users which belong to the domain supplied in _field-list_ (mode=monitored). Usage of mode=monitored requires ownage of the specified domain and prior configuration on haveibeenpwned.com. Default: mail.

_threshold_: Set how many days to look back for breaches. Default: 7 days.

_output_: Control whether to return the fetched and parsed data as plaintext or json formatted fields. Default: text.

_pastes_: Control whether to additionally query for account pastes or not, or only those with a timestamp when using mode=mail. Default: dated.

_field-list_: The fields in your Splunk search results that you want to query against the HIBP API. These fields should contain mail addresses or domain names depending on the chosen mode.

When using mode=mail, search performance is highly dependent on the number of queried mail addresses and your API key's rate limit. Expect 0.12 seconds on the highest tier API key and up to 6 seconds per mail address when using the lowest tier API key. This is to adhere to the API's acceptable use terms. Do not attempt to spam the search as it will only degrade the performance further. 


### Examples

Check a list of mail addresses from local logs for pwnage in the last year, also check for any related pastes

&nbsp;&nbsp;&nbsp;_search index=ad | table email | haveibeenpwned mode=mail threshold=365 pastes=all email_


Check a domain for breaches during the last month and output as json

&nbsp;&nbsp;&nbsp;_| makeresults | eval mydomain="mydomain.com" | haveibeenpwned mode=domain threshold=31 output=json mydomain_

Check if any mail addresses belonging to a domain you own were part of a breach in the last 7 days (requires previous configuration on haveibeenpwned.com)

&nbsp;&nbsp;&nbsp;_| makeresults | eval mydomain="mydomain.com" | haveibeenpwned mode=monitored mydomain_

Parts of the information retrieved when using mode=monitored might be null if no previous manual search concerning the domain was performed in your haveibeenpwned.com account.


## History

### v2.3.0

* Added query mode "monitored" to check if any mail addresses belonging to a domain you own were part of a breach
* Updated Python SDK to v1.7.4

### ...

### v2.2.0

* Fixed issue where domain names were mismatched
* Fixed issue where fields would not show up due to exceeding rate limits
* Added command parameter to output fetched data as json
* Added setting for API key rate limit, so sleeping intervals can be controlled
* Updated Python SDK

### ...

### v2.0.2

* Updated Splunk Python SDK to v1.6.15, removing a bug which can cause Splunk instances to hang

### v2.0.1

* Fixed file permissions for Splunk Cloud vetting

### v2.0.0

* Implemented Splunk Cloud compatibility by relying on Splunk Add-On Builder for the add-on setup/configuration. Thanks to lukemonahan!

* Improved conectivity tests, proxy and error handling

* Added custom role for non-privileged users

* Added add-on logo

s
## TODO / Known Issues

* Potentially add a mode to query the passwords API. As password hashes should not be stored in Splunk this should not be a valid use case.
* Currently only HTTP(S) proxies are supported and only Basic Authentication. Add support for SOCKS proxies and NTLM authentication.

