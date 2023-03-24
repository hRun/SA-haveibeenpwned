# SA-haveibeenpwned

A Splunk® add-on providing a custom search command _haveibeenpwned_ to query Troy Hunt's haveibeenpwned API (https://haveibeenpwned.com/api/v3/) for known breaches of your (company's) domains or your friends'/family's/enemies'/hardly distantly related someone's/employees'/colleagues' mail adresses.

Please respect people's privacy and adhere to the service's acceptable use (https://haveibeenpwned.com/API/v3#AcceptableUse). I tried respecting the limits posed on the API's use in the command's source code, which is why you'll have to have a little patience when querying for large amounts of mail addresses.

I was unsatisfied with the publicly available Splunk add-ons already providing this functionality as they either didn't allow control over what and how is queried for or didn't format the output to my wishes. So I came up with my own Splunk add-on implementing these missing features.

Cross-compatible with Python 2 and 3. Tested on Splunk Enterprise 9.0.2 and 8.2.3 on Windows, Linux and Splunk Cloud.

Licensed under http://www.apache.org/licenses/LICENSE-2.0.

* Authors: Harun Kuessner
* Version: 2.2.2


## Installation & Updating

Just unpack to _$SPLUNK_HOME/etc/apps_ on your Splunk search head and restart the instance. Use the deployer in a distributed environment.

**Important note on updating from version 2.1.0 to 2.2.x:** 

Due to changes in the HIBP API's rate limiting, a parameter to set the supplied API key's individual rate limit was added on the add-on's configuration page. It controls sleep intervals during search execution to prevent provoking API timeouts. The parameter is set to 10 requests per minute by default (current lowest tier). To make full use of your API plan, set it to the rate limit tied to the entered API key (as visible from https://haveibeenpwned.com/API/Key/Verify).

**Important note on updating to add-on version 2.x.x:** 

When updating from add-on version 1.x.x to 2.x.x, you'll be required to reconfigure used API key and proxies (see _Requirements & Setup_). Un-privileged users without the _list\_storage\_passwords_ capability will no longer be able to make use of _mode=mail_. A custom role _can\_query\_hibp_ is supplied to empower such users (including all negative implications this capability brings with it until Splunk finally decides to fix it).

For legacy Splunk environments, if you prefer a slimmer implementation or if the stated cpability limitations are not an option, please use add-on version 1.2.2. Overall functionality is exactly the same. 

Set _python.version=python2_ or _python.version=python3_ in _commands.conf_ if you would like to explicitly specify the Python version to use. Otherwise this will be determined by your instance's global settings. Set _python.version=python2_ in _restmap.conf_ if you experience issues with the app's configuration page on older Splunk instances.


## Requirements & Setup

Your Splunk instance requires acess to the internet (via a proxy) to query https://haveibeenpwned.com/api/v3/*. Configure proxies via the app's configuration page if required.

Unfortunately parts of the HIBP API now require an API key which you can obtain here: https://haveibeenpwned.com/API/Key. Specify your API key via the app's configuration page to be able to use _mode=mail_. _mode=domain_ will work without an API key.

If you require using a proxy, unfortunately currently only HTTP(S) proxies are supported and only Basic Authentication. Support for SOCKS proxies and NTLM authentication will be added in a later verion of the app.


## Usage

Use as a search command like so:

_search index=example | table email | haveibeenpwned [mode=<mail|domain>] [threshold=\<days>] [output=<text|json>] [pastes=\<all|dated|none>] \<field-list>_

_mode_: Control whether to query for breaches regarding one or multiple domains or specific mail addresses. Default: mail.

_threshold_: Set how many days to look back for breaches. Default: 7 days.

_output_: Control whether to return the fetched and parsed data as plaintext or json formatted fields. Default: text.

_pastes_: Control whether to additionally query for account pastes or not or only those with a timestamp when using mode=mail. Default: dated.

_\<field-list>_: The fields in your Splunk search results that you want to query against the HIBP API. These fields should contain mail addresses or domain names depending on the chosen mode.

When using mode=mail, search performance is highly dependent on the number of queried mail addresses and your API key's rate limit. Expect 0.12 seconds on the highest tier API key and up to 6 seconds per mail address when using the lowest tier API key. This is to adhere to the API's acceptable use terms. Do not attempt to spam the search as it will only degrade the performance further. 


### Examples

Check a list of mail addresses from local logs for pwnage in the last year, also check for any related pastes

&nbsp;&nbsp;&nbsp;_search index=ad | table email | haveibeenpwned mode=mail threshold=365 pastes=all email_


Check a domain for breaches during the last month and output as json

&nbsp;&nbsp;&nbsp;_| makeresults | eval mydomain="mydomain.com" | haveibeenpwned mode=domain threshold=31 output=json mydomain_


## History

### v2.2.3

* Updated Splunk Python SDK to v1.7.3, fixed a bug which caused proxy connections to hang


### v2.2.2

* Fixed metadata issue breaking Splunk Cloud compatibility

### v2.2.0

* Fixed issue where domain names were mismatched
* Fixed issue where fields would not show up due to exceeding rate limits
* Added command parameter to output fetched data as json
* Added setting for API key rate limit, so sleeping intervals can be controlled
* Updated python sdk

### v2.1.0

* Re-packaged using Splunk Add-On Builder 4.1.0
* Updated Splunk Python SDK to v1.6.19

### v2.0.5

* Bug fix

### v2.0.4

* Added appropriate reload triggers
* Updated Splunk Python SDK to v1.6.18 and moved to ./lib/ directory

### v2.0.3

* Repackaged using Splunk Add-On Builder v4.0.0
* Updated Splunk Python SDK to v1.6.16

### v2.0.2

* Updated Splunk Python SDK to v1.6.15, removing a bug which can cause Splunk instances to hang

### v2.0.1

* Fixed file permissions for Splunk Cloud vetting

### v2.0.0

* Implemented Splunk Cloud compatibility by relying on Splunk Add-On Builder for the add-on setup/configuration. Thanks to lukemonahan!

* Improved conectivity tests, proxy and error handling

* Added custom role for non-privileged users

* Added add-on logo

### v1.2.2

* Fixed a bug where the Splunk search would fail if a paste was found for an account but does not return a title or date

* Add option to control whether to report account pastes or not or just the ones with a timestamp

### v1.2.1

* Better connection state handling and URL encoding

* Updated to Splunklib 1.6.14

### v1.2.0

* Overall enhancements and bug fixes

* Implemented better sanity checks and error handling

## TODO / Known Issues

* Potentially add a mode to query the passwords API. As password hashes should not be stored in Splunk this should not be a valid use case.
* Currently only HTTP(S) proxies are supported and only Basic Authentication. Add support for SOCKS proxies and NTLM authentication.

