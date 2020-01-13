# Google Maps API Scanner
Used for determining whether a leaked/found Google Maps API Key is vulnerable to unauthorized access by other applications or not.  

***Usage:***
- Download `maps_api_scanner.py` file and run as: `python maps_api_scanner.py`.
- Paste API key wanted to test when asked. 
- Script will return `API key is vulnerable for XXX API!` message and the PoC link/code if determines any unauthorized access within this API key within any API's.

***Checked APIs:***
- Staticmap API
- Streetview API
- Embed API
- Directions API
- Geocode API
- Distance Matrix API
- Find Place From Text API
- Autocomplete API
- Elevation API
- Timezone API
- Roads API

***Not Checked APIs:***
- JavaScript API: Because JavaScript API needs manual confirmation from a web browser directly, checks are not conducted for that API. If the script didn't found any vulnerable endpoints above or JavaScript API also wanted to be tested, manual checks can be conducted on this API within going to https://developers.google.com/maps/documentation/javascript/tutorial URL & copying HTML code and changing 'key' parameter with the one wanted to test. After opening file on the browser, if loaded without errors, then the API key is also vulnerable for JavaScript API.
