import requests
import warnings
import json
import sys
import os
import shutil
from typing import Any

# Timeout for HTTP requests (seconds)
REQUEST_TIMEOUT = 15

# Common request kwargs (disable SSL verify for compatibility; use in tests only)
_REQUEST_KWARGS: dict[str, Any] = {"verify": False, "timeout": REQUEST_TIMEOUT}

# Column width used to align per-API progress lines and the summary table
_NAME_WIDTH = 24

# Color support. Auto-disabled when stdout is not a TTY (e.g. piping to a file);
# can be forced off with --no-color.
_COLORS = {
    "red": "\033[1;31;40m",
    "green": "\033[1;32;40m",
    "yellow": "\033[1;33;40m",
    "reset": "\033[0m",
}
_USE_COLOR = sys.stdout.isatty()


def _configure_proxy(proxy_url):
    """Add proxy settings to the shared request kwargs."""
    if proxy_url:
        _REQUEST_KWARGS["proxies"] = {"http": proxy_url, "https": proxy_url}


def _color(text, code="red"):
    """Wrap text in an ANSI color (no-op when colors are disabled)."""
    if not _USE_COLOR:
        return text
    return _COLORS.get(code, "") + text + _COLORS["reset"]


def _mask_key(text, apikey):
    """Replace occurrences of the API key with a masked form (AIza…xxxx)."""
    if not apikey or not text:
        return text
    if len(apikey) > 8:
        masked = apikey[:4] + "…" + apikey[-4:]
    else:
        masked = "…" + apikey[-4:]
    return text.replace(apikey, masked)


def _truncate(text, width):
    """Truncate long text to fit a column width, appending an ellipsis."""
    text = str(text)
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


def _error_message(response, keys=("error_message", "errorMessage")):
    """Safely extract error message from JSON response to avoid KeyError."""
    try:
        data = response.json()
        # Some APIs (e.g. Routes computeRouteMatrix) return an array of items; first element may contain error
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            data = data[0]
        if not isinstance(data, dict):
            raise TypeError
        for key in keys:
            if key in data:
                val = data[key]
                if isinstance(val, dict) and "message" in val:
                    return val["message"]
                if isinstance(val, str):
                    return val
        if "error" in data and isinstance(data["error"], dict):
            return data["error"].get("message", str(data["error"]))
    except (json.JSONDecodeError, TypeError):
        pass
    if response.content:
        try:
            return response.content[:500].decode("utf-8", errors="replace").strip()
        except Exception:
            return str(response.content[:200])
    return "Unknown error (status %s)" % getattr(response, "status_code", "?")


def _report_safe(results, name):
    """Record a non-vulnerable API and print a single compact progress line."""
    results.append({"name": name, "vulnerable": False, "cost": "", "poc": ""})
    print("  [ %s ] %-*s %s" % (_color("OK", "green"), _NAME_WIDTH, name, _color("restricted", "green")))


def _report_vulnerable(results, name, cost, poc):
    """Record a vulnerable API and print a single compact progress line."""
    results.append({"name": name, "vulnerable": True, "cost": cost, "poc": poc})
    print("  [ %s ] %-*s %s" % (_color("!!", "red"), _NAME_WIDTH, name, _color("VULNERABLE", "red")))


def _print_banner(apikey, total_apis):
    """Print the intro banner (suppressed with --no-banner)."""
    print("G-Maps API Scanner v1.1.0")
    print("Key: " + _mask_key(apikey, apikey))
    print("Scanning %d Google APIs..." % total_apis)
    print()


def _render_summary(results, mask_key=False, apikey=None):
    """Render the final table of vulnerable APIs only."""
    vulnerable = [r for r in results if r["vulnerable"]]
    total = len(results)
    vuln_count = len(vulnerable)

    print()
    print(_color("====================  SUMMARY  ====================", "yellow"))
    if vuln_count == 0:
        print(_color("  No vulnerable APIs found - the key appears to be restricted.", "green"))
        return
    print(_color("  %d of %d APIs are vulnerable to unauthorized use." % (vuln_count, total), "red"))
    print()

    if sys.stdout.isatty():
        term_width = shutil.get_terminal_size((120, 24)).columns
    else:
        term_width = 110
    cost_w = 30
    poc_w = max(30, term_width - _NAME_WIDTH - cost_w - 6)
    sep = "  " + "-" * _NAME_WIDTH + "  " + "-" * cost_w + "  " + "-" * poc_w
    print("  %-*s  %-*s  %s" % (_NAME_WIDTH, "API", cost_w, "Impact / cost", "PoC"))
    print(sep)
    for r in vulnerable:
        poc = _mask_key(r["poc"], apikey) if mask_key else r["poc"]
        print("  %-*s  %-*s  %s" % (_NAME_WIDTH, r["name"], cost_w, r["cost"], _truncate(poc, poc_w)))
    print()
    print("  Pricing reference: https://cloud.google.com/maps-platform/pricing")
    print("  Billing reference: https://developers.google.com/maps/billing/gmp-billing")


def scan_gmaps(apikey, jsapi=False, proxy=None, mask_key=False, no_color=False, no_banner=False):
	global _USE_COLOR
	if no_color:
		_USE_COLOR = False
	_configure_proxy(proxy)
	results = []

	if not no_banner:
		_print_banner(apikey, 25)

	url = "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.status_code == 200:
		_report_vulnerable(results, "Staticmap", "$2 per 1000 requests", url)
	else:
		_report_safe(results, "Staticmap")

	url = "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.status_code == 200:
		_report_vulnerable(results, "Streetview", "$7 per 1000 requests", url)
	else:
		_report_safe(results, "Streetview")

	url = "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key="+apikey
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		_report_vulnerable(results, "Directions", "$5 per 1000 requests (Advanced: $10)", url)
	else:
		_report_safe(results, "Directions")

	url = "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		_report_vulnerable(results, "Geocode", "$5 per 1000 requests", url)
	else:
		_report_safe(results, "Geocode")

	url = "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.659569%2C-73.933783&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		_report_vulnerable(results, "Distance Matrix", "$5 per 1000 elements (Advanced: $10)", url)
	else:
		_report_safe(results, "Distance Matrix")

	url = "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key="+apikey
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		_report_vulnerable(results, "Find Place From Text", "$17 per 1000 elements", url)
	else:
		_report_safe(results, "Find Place From Text")

	url = "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		_report_vulnerable(results, "Autocomplete", "$2.83 per 1000 requests (Per Session: $17)", url)
	else:
		_report_safe(results, "Autocomplete")

	url = "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		_report_vulnerable(results, "Elevation", "$5 per 1000 requests", url)
	else:
		_report_safe(results, "Elevation")

	url = "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("errorMessage") < 0:
		_report_vulnerable(results, "Timezone", "$5 per 1000 requests", url)
	else:
		_report_safe(results, "Timezone")

	url = "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error") < 0:
		_report_vulnerable(results, "Nearest Roads", "$10 per 1000 requests", url)
	else:
		_report_safe(results, "Nearest Roads")

	url = "https://www.googleapis.com/geolocation/v1/geolocate?key="+apikey 
	postdata = {'considerIp': 'true'}
	response = requests.post(url, data=postdata, **_REQUEST_KWARGS)
	if response.text.find("error") < 0:
		poc = "curl -s -X POST -H \"Content-Type: application/json\" -d '{\"considerIp\":\"true\"}' \""+url+"\""
		_report_vulnerable(results, "Geolocation", "$5 per 1000 requests", poc)
	else:
		_report_safe(results, "Geolocation")

	url = "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error") < 0:
		_report_vulnerable(results, "Route to Traveled", "$10 per 1000 requests", url)
	else:
		_report_safe(results, "Route to Traveled")

	url = "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error") < 0:
		_report_vulnerable(results, "Speed Limit-Roads", "$20 per 1000 requests", url)
	else:
		_report_safe(results, "Speed Limit-Roads")

	url = "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		_report_vulnerable(results, "Place Details", "$17 per 1000 requests", url)
	else:
		_report_safe(results, "Place Details")

	url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		_report_vulnerable(results, "Nearby Search-Places", "$32 per 1000 requests", url)
	else:
		_report_safe(results, "Nearby Search-Places")

	url = "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		_report_vulnerable(results, "Text Search-Places", "$32 per 1000 requests", url)
	else:
		_report_safe(results, "Text Search-Places")

	url = "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key="+apikey 
	response = requests.get(url, allow_redirects=False, **_REQUEST_KWARGS)
	if response.status_code == 302:
		_report_vulnerable(results, "Places Photo", "$7 per 1000 requests", url)
	else:
		_report_safe(results, "Places Photo")

	# Address Validation API (POST)
	url = "https://addressvalidation.googleapis.com/v1:validateAddress?key=" + apikey
	postdata = json.dumps({"address": {"regionCode": "US", "addressLines": ["1600 Amphitheatre Pkwy, Mountain View, CA"]}})
	response = requests.post(url, data=postdata, headers={"Content-Type": "application/json"}, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0:
		poc = "curl -s -X POST -H \"Content-Type: application/json\" -d '{\"address\":{\"regionCode\":\"US\",\"addressLines\":[\"1600 Amphitheatre Pkwy, Mountain View, CA\"]}}' \""+url+"\""
		_report_vulnerable(results, "Address Validation", "$5 per 1000 requests", poc)
	else:
		_report_safe(results, "Address Validation")

	# Air Quality API (POST)
	url = "https://airquality.googleapis.com/v1/currentConditions:lookup?key=" + apikey
	postdata = json.dumps({"location": {"latitude": 37.419734, "longitude": -122.0827784}})
	response = requests.post(url, data=postdata, headers={"Content-Type": "application/json"}, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0:
		poc = "curl -s -X POST -H \"Content-Type: application/json\" -d '{\"location\":{\"latitude\":37.419734,\"longitude\":-122.0827784}}' \""+url+"\""
		_report_vulnerable(results, "Air Quality", "Paid per request", poc)
	else:
		_report_safe(results, "Air Quality")

	# Aerial View API (GET) - video metadata lookup
	url = "https://aerialview.googleapis.com/v1/videos:lookupVideoMetadata?key=" + apikey + "&address=600%20Montgomery%20St%2C%20San%20Francisco%2C%20CA%2094111"
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0:
		_report_vulnerable(results, "Aerial View", "Paid per request", url)
	else:
		_report_safe(results, "Aerial View")

	# Routes API - computeRoutes (POST, requires field mask)
	url = "https://routes.googleapis.com/directions/v2:computeRoutes?key=" + apikey
	headers = {"Content-Type": "application/json", "X-Goog-FieldMask": "routes.duration,routes.distanceMeters,routes.polyline.encodedPolyline"}
	body = {
		"origin": {"location": {"latLng": {"latitude": 37.419734, "longitude": -122.0827784}}},
		"destination": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}},
		"travelMode": "DRIVE",
	}
	response = requests.post(url, data=json.dumps(body), headers=headers, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0 and "routes" in response.text:
		poc = "curl -s -X POST -H \"Content-Type: application/json\" -H \"X-Goog-FieldMask: routes.duration,routes.distanceMeters,routes.polyline.encodedPolyline\" -d '{\"origin\":{\"location\":{\"latLng\":{\"latitude\":37.419734,\"longitude\":-122.0827784}}},\"destination\":{\"location\":{\"latLng\":{\"latitude\":37.4220,\"longitude\":-122.0841}}},\"travelMode\":\"DRIVE\"}' \""+url+"\""
		_report_vulnerable(results, "Routes (computeRoutes)", "Paid per request", poc)
	else:
		_report_safe(results, "Routes (computeRoutes)")

	# Routes API - computeRouteMatrix (POST)
	url = "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key=" + apikey
	headers = {"Content-Type": "application/json", "X-Goog-FieldMask": "originIndex,destinationIndex,status,distanceMeters,duration"}
	body = {
		"origins": [{"waypoint": {"location": {"latLng": {"latitude": 37.419734, "longitude": -122.0827784}}}}],
		"destinations": [
			{"waypoint": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}}},
			{"waypoint": {"location": {"latLng": {"latitude": 37.4250, "longitude": -122.0860}}}},
		],
		"travelMode": "DRIVE",
	}
	response = requests.post(url, data=json.dumps(body), headers=headers, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0:
		poc = "curl -s -X POST -H \"Content-Type: application/json\" -H \"X-Goog-FieldMask: originIndex,destinationIndex,status,distanceMeters,duration\" -d '{\"origins\":[{\"waypoint\":{\"location\":{\"latLng\":{\"latitude\":37.419734,\"longitude\":-122.0827784}}}}],\"destinations\":[{\"waypoint\":{\"location\":{\"latLng\":{\"latitude\":37.4220,\"longitude\":-122.0841}}}},{\"waypoint\":{\"location\":{\"latLng\":{\"latitude\":37.4250,\"longitude\":-122.0860}}}}],\"travelMode\":\"DRIVE\"}' \""+url+"\""
		_report_vulnerable(results, "Routes (Route Matrix)", "Paid per element", poc)
	else:
		_report_safe(results, "Routes (Route Matrix)")

	url = "https://fcm.googleapis.com/fcm/send" 
	postdata = "{'registration_ids':['ABC']}"
	response = requests.post(url, data=postdata, **_REQUEST_KWARGS, headers={'Content-Type':'application/json','Authorization':'key='+apikey})
	if response.status_code == 200:
		poc = "curl --header \"Authorization: key="+apikey+"\" --header Content-Type:\"application/json\" https://fcm.googleapis.com/fcm/send -d '{\"registration_ids\":[\"ABC\"]}'"
		_report_vulnerable(results, "FCM", "https://abss.me/posts/fcm-takeover/", poc)
	else:
		_report_safe(results, "FCM")

	# Gemini Files API (GET)
	url = "https://generativelanguage.googleapis.com/v1beta/files?key=" + apikey
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.status_code == 200:
		poc = url + " - data leak risk: https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules"
		_report_vulnerable(results, "Gemini (Files)", "Data leak risk", poc)
	else:
		_report_safe(results, "Gemini (Files)")

	# Gemini Cached Contents API (GET)
	url = "https://generativelanguage.googleapis.com/v1beta/cachedContents?key=" + apikey
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.status_code == 200:
		_report_vulnerable(results, "Gemini (Cache)", "Data leak risk", url)
	else:
		_report_safe(results, "Gemini (Cache)")

	_render_summary(results, mask_key=mask_key, apikey=apikey)

	if jsapi:
		f = open("jsapi_test.html", "w+")
		f.write('<!DOCTYPE html><html><head><script src="https://maps.googleapis.com/maps/api/js?key='+apikey+'&callback=initMap&libraries=&v=weekly" defer></script><style type="text/css">#map{height:100%;}html,body{height:100%;margin:0;padding:0;}</style><script>let map;function initMap(){map=new google.maps.Map(document.getElementById("map"),{center:{lat:-34.397,lng:150.644},zoom:8,});}</script></head><body><div id="map"></div></body></html>')
		f.close()
		print("jsapi_test.html file is created for manual confirmation. Open it at your browser and observe whether the map is successfully loaded or not.")
		print("If you see 'Sorry! Something went wrong.' error on the page, it means that API key is not allowed to be used at JavaScript API.")
		input("Press enter to delete jsapi_test.html after manual confirmation is conducted.")
		os.remove("jsapi_test.html")
	else:
		print("\nSkipping JavaScript API test (use --jsapi to enable).")
	print("Operation is over. Thanks for using G-Maps API Scanner!")
	return True


def main() -> None:
	warnings.filterwarnings("ignore")
	args = sys.argv[1:]

	jsapi = "--jsapi" in args
	args = [a for a in args if a != "--jsapi"]

	mask_key = "--mask-key" in args
	args = [a for a in args if a != "--mask-key"]

	no_color = "--no-color" in args
	args = [a for a in args if a != "--no-color"]

	no_banner = "--no-banner" in args
	args = [a for a in args if a != "--no-banner"]

	# Extract --proxy / -p value
	proxy = None
	for flag in ("--proxy", "-p"):
		if flag in args:
			idx = args.index(flag)
			if idx + 1 < len(args):
				proxy = args[idx + 1]
				args = args[:idx] + args[idx + 2:]
			else:
				print("Missing proxy URL after %s, aborting." % flag)
				_print_usage()
				return
			break

	if proxy:
		print("Using proxy: " + proxy)

	if len(args) > 0:
		if args[0] == "--api-key" or args[0] == "-a":
			if len(args) > 1:
				scan_gmaps(args[1], jsapi=jsapi, proxy=proxy, mask_key=mask_key, no_color=no_color, no_banner=no_banner)
			else:
				print("Missing api key, aborting.")
				_print_usage()
		elif args[0] == "--help" or args[0] == "-h":
			_print_usage()
		else:
			print("Invalid arguments, aborting.")
			_print_usage()
	else:
		apikey = input("Please enter the Google Maps API key you wanted to test: ")
		scan_gmaps(apikey, jsapi=jsapi, proxy=proxy, mask_key=mask_key, no_color=no_color, no_banner=no_banner)


def _print_usage() -> None:
	print("Usage: python maps_api_scanner.py [--api-key KEY] [--proxy URL] [--jsapi] [--mask-key] [--no-color] [--no-banner]")
	print("       gmapsapiscanner [--api-key KEY] [--proxy URL] [--jsapi] [--mask-key] [--no-color] [--no-banner]")
	print("  --api-key, -a   API key to test (otherwise prompted for input)")
	print("  --proxy, -p     HTTP/HTTPS/SOCKS proxy URL (e.g. http://127.0.0.1:8080)")
	print("  --jsapi         Run the interactive JavaScript API test (default: skipped)")
	print("  --mask-key      Hide the API key in printed PoC links/commands (AIza…xxxx)")
	print("  --no-color      Disable ANSI colors (auto-disabled when piping to a file)")
	print("  --no-banner     Hide the intro banner")
	print("  --help, -h      Show this message")

if __name__ == "__main__":
    main()
