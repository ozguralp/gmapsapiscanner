# Google Maps API Scanner
Used for determining whether a leaked/found Google Maps API Key is vulnerable to unauthorized access by other applications or not.  

***Blog Post #1:*** https://medium.com/bugbountywriteup/unauthorized-google-maps-api-key-usage-cases-and-why-you-need-to-care-1ccb28bf21e

***Blog Post #2:*** https://medium.com/bugbountywriteup/google-maps-api-not-the-key-bugs-that-i-found-over-the-years-781840fc82aa

***Usage:***
- Download `maps_api_scanner.py` file and run as: `python maps_api_scanner.py`.
- Paste API key wanted to test when asked. 
- Script will return `API key is vulnerable for XXX API!` message and the PoC link/code if determines any unauthorized access within this API key within any API's.
- If you want to use `python3`, download `maps_api_scanner_python3.py` file and run as: `python3 maps_api_scanner_python3.py`.

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
- JavaScript API

***Notes:***
- Because JavaScript API needs manual confirmation from a web browser directly, checks are not conducted for that API. If the script didn't found any vulnerable endpoints above or JavaScript API also wanted to be tested, manual checks can be conducted on this API within going to https://developers.google.com/maps/documentation/javascript/tutorial URL & copying HTML code and changing 'key' parameter with the one wanted to test. After opening file on the browser, if loaded without errors, then the API key is also vulnerable for JavaScript API.
- For Staticmap, Streetview and Embed API's, if used from another domain instead of just testing from browser; whether referer checks are enabled or not, script will return it as vulnerable. If you cannot reproduce the vulnerability via browser, please read the "Blog Post #2" for more information & a better understanding about what is going on. 
- If you find any Google Maps API's which are not mentioned in this document/script, ping me via Twitter with details so I can also add them.
