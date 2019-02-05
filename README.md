# SA-haveibeenpwned

A Splunk® add-on providing a custom search command _haveibeenpwned_ to query Troy Hunt's haveibeenpwned API (https://haveibeenpwned.com/api/v2/) for known breaches of your (company's) domains or your friend's/family's/enemies'/hardly distantly related someone's/employee's/colleague's mail adresses.

Please respect people's privacy and adhere to the service's acceptable use (https://haveibeenpwned.com/API/v2#AcceptableUse).

I was unsatisfied with the publicly available Splunk add-ons already providing this functionality as they either didn't allow control over what and how is queried for or didn't format the output to my wishes. So I came up with my own Splunk add-on implementing these missing features. I tried respecting the limits posed on the API's use in the command's source code.

Tested on Splunk Enterprise 7.1.3.

## Installation

Just unpack to $SPLUNK_HOME/etc/apps on your Splunk search head and restart the instance. Use the deployer in a distributed environment.

## Requirements

Your Splunk instance requires acess to the internet (via a proxy) to query https://haveibeenpwned.com/api/v2/\*.

## TODO / Known Issues

Add a proxy configuration page.

Add some more error handling.

Add some better handling of HTTP response code 429.

Potentially set a custom user agent for HTTP requests.

