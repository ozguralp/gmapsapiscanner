# Google Maps API Scanner

Used for determining whether a leaked/found Google Maps API Key is vulnerable to unauthorized access by other applications or not.  

***[Blog Post #1 - Unauthorized Google Maps API Key Usage Cases, and Why You Need to Care](https://medium.com/bugbountywriteup/unauthorized-google-maps-api-key-usage-cases-and-why-you-need-to-care-1ccb28bf21e)***

***[Blog Post #2 - Google Maps API (Not the Key) Bugs That I Found Over the Years](https://medium.com/bugbountywriteup/google-maps-api-not-the-key-bugs-that-i-found-over-the-years-781840fc82aa)***

***Please note that most of the bug bounty platforms marking this vulnerability type as informational/low impact. So please make sure that the platform or program is accepting this kind of issues before reporting.***

***Usage:***

- Either download the Python file directly or install it with **pip** or **pipx**.
- Script prints one compact line per API while scanning, then a clean summary table of only the vulnerable APIs with their PoC link/command.
- The JavaScript API test is **skipped by default**; enable it explicitly with `--jsapi`.

```
pipx install git+https://github.com/ozguralp/gmapsapiscanner
gmapsapiscanner --api-key KEY
gmapsapiscanner --api-key KEY --mask-key      # hide the key in printed PoC links/commands
gmapsapiscanner --api-key KEY --no-color      # no ANSI colors (auto-disabled when piping)
gmapsapiscanner --api-key KEY --no-banner     # skip the intro banner (cleaner screenshots)
gmapsapiscanner --api-key KEY --jsapi         # run the interactive JavaScript API test
gmapsapiscanner --api-key KEY --proxy http://127.0.0.1:8080
```

***Output:***

```
G-Maps API Scanner v1.1.0
Key: AIza…9Zc2
Scanning 25 Google APIs...

  [ OK ] Staticmap            restricted
  [ OK ] Streetview           restricted
  [ !! ] Directions           VULNERABLE
  [ OK ] Geocode              restricted
  ...

====================  SUMMARY  ====================
  2 of 25 APIs are vulnerable to unauthorized use.

  API          Impact / cost                    PoC
  ------------ ------------------------------  -----------------------------------------
  Staticmap    $2 per 1000 requests            https://maps.googleapis.com/maps/api/staticmap?…&key=AIza…9Zc2
  Directions   $5 per 1000 requests            https://maps.googleapis.com/maps/api/directions/json?…&key=AIza…9Zc2

  Pricing reference: https://cloud.google.com/maps-platform/pricing
  Billing reference: https://developers.google.com/maps/billing/gmp-billing
```

***Checked APIs:***
- Staticmap API
- Streetview API
- <s>Embed (Basic-Free) API</s> (No longer checked since it is completely free.)
- <s>Embed (Advanced-Paid) API</s> (No longer checked since it is completely free.)
- Directions API
- Geocode API
- Distance Matrix API
- Find Place From Text API
- Autocomplete API
- Elevation API
- Timezone API
- Roads API (Nearest Roads, Snap to Roads, Speed Limits)
- Geolocation API
- Route to Traveled API
- Speed Limit-Roads API
- Place Details API
- Nearby Search-Places API
- Text Search-Places API
- Places Photo API
- Address Validation API
- Air Quality API
- Aerial View API
- Routes API (computeRoutes, computeRouteMatrix)
- <s>Playable Locations API</s> (API is deprecated.)
- FCM API

***Semi-Auto Checked APIs:***
- JavaScript API (opt-in with `--jsapi`; skipped by default so scans work non-interactively)

***Notes:***
- Because JavaScript API needs manual confirmation from a web browser directly, only file is created via the script for manual checks/confirmation.
- The JavaScript API test is disabled by default. Use `--jsapi` to enable it (requires manual confirmation + file creation).
- For Staticmap, Streetview and Embed API's, if used from another domain instead of just testing from browser; whether referer checks are enabled or not on the server-side for the key, script still could return it as vulnerable due to a server-side vulnerability. If you cannot reproduce the vulnerability via browser while the script says so, please read the ***Blog Post #2*** for more information & a better understanding about what is going on. 
- If you find any Google Maps API's which are not mentioned in this document/script, create an issue with details so I can also add them.
- Special thanks to [Yatin](https://twitter.com/ysirpaul) for his contributions on both discovery of additional API's & cost information!


## Docker
To run this script in a Dockerized Alpine Linux environment, use the following commands:
```
docker build -t google_maps_api_scanner .
docker run --rm -v $(pwd):/opt/html -i docker.io/library/google_maps_api_scanner <api key>
```
