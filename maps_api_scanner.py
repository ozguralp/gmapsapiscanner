import requests
import warnings
import json
import sys
import os

# Timeout for HTTP requests (seconds)
REQUEST_TIMEOUT = 15

# Common request kwargs (disable SSL verify for compatibility; use in tests only)
_REQUEST_KWARGS = {"verify": False, "timeout": REQUEST_TIMEOUT}


def _error_message(response, keys=("error_message", "errorMessage")):
    """Safely extract error message from JSON response to avoid KeyError."""
    try:
        data = response.json()
        # Some APIs (e.g. Routes computeRouteMatrix) return an array of items; first element may contain error
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            data = data[0]
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


def scan_gmaps(apikey, skip_jsapi=False):
	vulnerable_apis = []
	url = "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.status_code == 200:
		print("API key is \033[1;31;40mvulnerable\033[0m for Staticmap API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Staticmap 			|| $2 per 1000 requests")
	elif b"PNG" in response.content:
		print("API key is not vulnerable for Staticmap API.")
		print("Reason: Manually check the "+url+" to view the reason.")
	else:
		print("API key is not vulnerable for Staticmap API.")
		print("Reason: "+ str(response.content))

	url = "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.status_code == 200:
		print("API key is \033[1;31;40mvulnerable\033[0m for Streetview API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Streetview 			|| $7 per 1000 requests")
	elif b"PNG" in response.content:
		print("API key is not vulnerable for Streetview API.")
		print("Reason: Manually check the "+url+" to view the reason.")
	else:
		print("API key is not vulnerable for Streetview API.")
		print("Reason: "+ str(response.content))

	url = "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key="+apikey
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Directions API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Directions 			|| $5 per 1000 requests")
		vulnerable_apis.append("Directions (Advanced) 	|| $10 per 1000 requests")
	else:
		print("API key is not vulnerable for Directions API.")
		print("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Geocode API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Geocode 			|| $5 per 1000 requests")
	else:
		print("API key is not vulnerable for Geocode API.")
		print("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Distance Matrix API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Distance Matrix 		|| $5 per 1000 elements")
		vulnerable_apis.append("Distance Matrix (Advanced) 	|| $10 per 1000 elements")
	else:
		print("API key is not vulnerable for Distance Matrix API.")
		print("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key="+apikey
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Find Place From Text API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Find Place From Text 		|| $17 per 1000 elements")
	else:
		print("API key is not vulnerable for Find Place From Text API.")
		print("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Autocomplete API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Autocomplete 			|| $2.83 per 1000 requests")
		vulnerable_apis.append("Autocomplete Per Session 	|| $17 per 1000 requests")
	else:
		print("API key is not vulnerable for Autocomplete API.")
		print("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Elevation API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Elevation 			|| $5 per 1000 requests")
	else:
		print("API key is not vulnerable for Elevation API.")
		print("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("errorMessage") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Timezone API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Timezone 			|| $5 per 1000 requests")
	else:
		print("API key is not vulnerable for Timezone API.")
		print("Reason: "+ _error_message(response, ("errorMessage", "error_message")))

	url = "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Nearest Roads API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Nearest Roads 		|| $10 per 1000 requests")
	else:
		print("API key is not vulnerable for Nearest Roads API.")
		print("Reason: "+ _error_message(response, ("error",)))

	url = "https://www.googleapis.com/geolocation/v1/geolocate?key="+apikey 
	postdata = {'considerIp': 'true'}
	response = requests.post(url, data=postdata, **_REQUEST_KWARGS)
	if response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Geolocation API! Here is the PoC curl command which can be used from terminal:")
		print("curl -i -s -k  -X $'POST' -H $'Host: www.googleapis.com' -H $'Content-Length: 22' --data-binary $'{\"considerIp\": \"true\"}' $'"+url+"'")
		vulnerable_apis.append("Geolocation 			|| $5 per 1000 requests")
	else:
		print("API key is not vulnerable for Geolocation API.")
		print("Reason: "+ _error_message(response, ("error",)))

	url = "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Route to Traveled API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Route to Traveled 		|| $10 per 1000 requests")
	else:
		print("API key is not vulnerable for Route to Traveled API.")
		print("Reason: "+ _error_message(response, ("error",)))

	url = "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Speed Limit-Roads API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Speed Limit-Roads 		|| $20 per 1000 requests")
	else:
		print("API key is not vulnerable for Speed Limit-Roads API.")
		print("Reason: "+ _error_message(response, ("error",)))

	url = "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Place Details API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Place Details 		|| $17 per 1000 requests")
	else:
		print("API key is not vulnerable for Place Details API.")
		print("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Nearby Search-Places API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Nearby Search-Places		|| $32 per 1000 requests")
	else:
		print("API key is not vulnerable for Nearby Search-Places API.")
		print("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Text Search-Places API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Text Search-Places 		|| $32 per 1000 requests")
	else:
		print("API key is not vulnerable for Text Search-Places API.")
		print("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key="+apikey 
	response = requests.get(url, **{**_REQUEST_KWARGS, "allow_redirects": False})
	if response.status_code == 302:
		print("API key is \033[1;31;40mvulnerable\033[0m for Places Photo API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Places Photo 			|| $7 per 1000 requests")
	else:
		print("API key is not vulnerable for Places Photo API.")
		print("Reason: Verbose responses are not enabled for this API, cannot determine the reason.")

	# Address Validation API (POST)
	url = "https://addressvalidation.googleapis.com/v1:validateAddress?key=" + apikey
	postdata = json.dumps({"address": {"regionCode": "US", "addressLines": ["1600 Amphitheatre Pkwy, Mountain View, CA"]}})
	response = requests.post(url, data=postdata, headers={"Content-Type": "application/json"}, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Address Validation API! Here is the PoC curl command:")
		print('curl -X POST -H "Content-Type: application/json" -d \'{"address":{"regionCode":"US","addressLines":["1600 Amphitheatre Pkwy"]}}\' "' + url.replace("?key=" + apikey, "?key=YOUR_KEY") + '"')
		vulnerable_apis.append("Address Validation 		|| $5 per 1000 requests")
	else:
		print("API key is not vulnerable for Address Validation API.")
		print("Reason: " + _error_message(response, ("error",)))

	# Air Quality API (POST)
	url = "https://airquality.googleapis.com/v1/currentConditions:lookup?key=" + apikey
	postdata = json.dumps({"location": {"latitude": 37.419734, "longitude": -122.0827784}})
	response = requests.post(url, data=postdata, headers={"Content-Type": "application/json"}, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Air Quality API! Here is the PoC curl command:")
		print('curl -X POST -H "Content-Type: application/json" -d \'{"location":{"latitude":37.42,"longitude":-122.08}}\' "' + url.replace("?key=" + apikey, "?key=YOUR_KEY") + '"')
		vulnerable_apis.append("Air Quality 			|| Paid per request")
	else:
		print("API key is not vulnerable for Air Quality API.")
		print("Reason: " + _error_message(response, ("error",)))

	# Aerial View API (GET) - video metadata lookup
	url = "https://aerialview.googleapis.com/v1/videos:lookupVideoMetadata?key=" + apikey + "&address=600%20Montgomery%20St%2C%20San%20Francisco%2C%20CA%2094111"
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Aerial View API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Aerial View 			|| Paid per request")
	else:
		print("API key is not vulnerable for Aerial View API.")
		print("Reason: " + _error_message(response, ("error",)))

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
		print("API key is \033[1;31;40mvulnerable\033[0m for Routes API (computeRoutes)! Here is the PoC curl command:")
		print('curl -X POST -H "Content-Type: application/json" -H "X-Goog-FieldMask: routes.duration,routes.distanceMeters" -d \'{"origin":{"location":{"latLng":{"latitude":37.42,"longitude":-122.08}}},"destination":{"location":{"latLng":{"latitude":37.43,"longitude":-122.09}}},"travelMode":"DRIVE"}\' "' + url.replace("?key=" + apikey, "?key=YOUR_KEY") + '"')
		vulnerable_apis.append("Routes (computeRoutes) 	|| Paid per request")
	else:
		print("API key is not vulnerable for Routes API (computeRoutes).")
		print("Reason: " + _error_message(response, ("error",)))

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
		print("API key is \033[1;31;40mvulnerable\033[0m for Routes API (computeRouteMatrix)! Here is the PoC curl command:")
		print('curl -X POST -H "Content-Type: application/json" -H "X-Goog-FieldMask: originIndex,destinationIndex,status,distanceMeters,duration" -d \'{"origins":[{"waypoint":{"location":{"latLng":{"latitude":37.42,"longitude":-122.08}}}}],"destinations":[{"waypoint":{"location":{"latLng":{"latitude":37.43,"longitude":-122.09}}}}],"travelMode":"DRIVE"}\' "' + url.replace("?key=" + apikey, "?key=YOUR_KEY") + '"')
		vulnerable_apis.append("Routes (Route Matrix) 	|| Paid per element")
	else:
		print("API key is not vulnerable for Routes API (computeRouteMatrix).")
		print("Reason: " + _error_message(response, ("error",)))

	url = "https://fcm.googleapis.com/fcm/send" 
	postdata = "{'registration_ids':['ABC']}"
	response = requests.post(url, data=postdata, **_REQUEST_KWARGS, headers={'Content-Type':'application/json','Authorization':'key='+apikey})
	if response.status_code == 200:
		print("API key is \033[1;31;40mvulnerable\033[0m for FCM API! Here is the PoC curl command which can be used from terminal:")
		print("curl --header \"Authorization: key="+apikey+"\" --header Content-Type:\"application/json\" https://fcm.googleapis.com/fcm/send -d '{\"registration_ids\":[\"ABC\"]}'")
		vulnerable_apis.append("FCM Takeover 			|| https://abss.me/posts/fcm-takeover/")
	else:
		print("API key is not vulnerable for FCM API.")
		reason_found = False
		for line in response.iter_lines():
			if line and b"TITLE" in line:
				try:
					msg = line.decode("utf-8", errors="replace").split("TITLE")[1].split("<")[0].replace(">", "").strip()
					if msg:
						print("Reason: " + msg)
						reason_found = True
						break
				except (IndexError, AttributeError):
					pass
		if not reason_found:
			print("Reason: " + _error_message(response, ("error",)) if response.content else ("HTTP %s" % response.status_code))
	
	# Gemini Files API (GET)
    url = "https://generativelanguage.googleapis.com/v1beta/files?key="+apikey
    response = requests.get(url, **_REQUEST_KWARGS)
    if response.status_code == 200:
        print("API key is \033[1;31;40mvulnerable\033[0m for Gemini Files API! Here is the PoC link:")
        print(url)
        vulnerable_apis.append("Gemini (Files)           || Data Leak Risk https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules")
    else:
        print("API key is not vulnerable for Gemini Files API.")
        print("Reason: "+ _error_message(response, ("error",)))

    # Gemini Cached Contents API (GET)
    url = "https://generativelanguage.googleapis.com/v1beta/cachedContents?key="+apikey
    response = requests.get(url, **_REQUEST_KWARGS)
    if response.status_code == 200:
        print("API key is \033[1;31;40mvulnerable\033[0m for Gemini Cached Contents API! Here is the PoC link:")
        print(url)
        vulnerable_apis.append("Gemini (Cache)           || Data Leak Risk")
    else:
        print("API key is not vulnerable for Gemini Cached Contents API.")
        print("Reason: "+ _error_message(response, ("error",)))
	

	print("-------------------------------------------------------------")
	print("  Results 			|| Cost Table/Reference to Exploit:")
	print("-------------------------------------------------------------")
	for i in range (len(vulnerable_apis)):
	    print("- " + vulnerable_apis[i])
	print("-------------------------------------------------------------")
	print("Reference for up-to-date pricing:")
	print("https://cloud.google.com/maps-platform/pricing")
	print("https://developers.google.com/maps/billing/gmp-billing")
	if skip_jsapi:
		print("Skipping JavaScript API test (--no-jsapi).")
	else:
		jsapi = input("Do you want to conduct tests for Javascript API? (Will need manual confirmation + file creation) (Y/N)")
		if jsapi == "Y" or jsapi == "y":
			f = open("jsapi_test.html","w+")
			f.write('<!DOCTYPE html><html><head><script src="https://maps.googleapis.com/maps/api/js?key='+apikey+'&callback=initMap&libraries=&v=weekly" defer></script><style type="text/css">#map{height:100%;}html,body{height:100%;margin:0;padding:0;}</style><script>let map;function initMap(){map=new google.maps.Map(document.getElementById("map"),{center:{lat:-34.397,lng:150.644},zoom:8,});}</script></head><body><div id="map"></div></body></html>')
			print("jsapi_test.html file is created for manual confirmation. Open it at your browser and observe whether the map is successfully loaded or not.")
			f.close()
			print("If you see 'Sorry! Something went wrong.' error on the page, it means that API key is not allowed to be used at JavaScript API.")
			result = input("Press enter again for deletion of jsapi_test.html file automatically after manual confirmation is conducted.")
			os.remove("jsapi_test.html")
	print("Operation is over. Thanks for using G-Maps API Scanner!")
	return True

def main() -> None:
	warnings.filterwarnings("ignore")
	args = sys.argv[1:]
	skip_jsapi = "--no-jsapi" in args
	if skip_jsapi:
		args = [a for a in args if a != "--no-jsapi"]
	if len(args) > 0:
		if args[0] == "--api-key" or args[0] == "-a":
			if len(args) > 1:
				scan_gmaps(args[1], skip_jsapi=skip_jsapi)
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
		scan_gmaps(apikey, skip_jsapi=skip_jsapi)


def _print_usage() -> None:
	print("Usage: python maps_api_scanner.py [--api-key KEY] [--no-jsapi]")
	print("       gmapsapiscanner [--api-key KEY] [--no-jsapi]")
	print("  --api-key, -a   API key to test (otherwise prompted for input)")
	print("  --no-jsapi      Skip the interactive JavaScript API test (useful for CI/automation)")
	print("  --help, -h      Show this message")

if __name__ == "__main__":
    main()

