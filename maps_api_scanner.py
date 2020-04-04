import requests
import warnings 
import json

vulnerable_apis = []
warnings.filterwarnings("ignore")
apikey = raw_input("Please enter the Google Maps API key you wanted to test: ")
url = "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key="+apikey 
response = requests.get(url, verify=False)
if response.status_code == 200:
	print (" API key is \033[1;31;40m vulnerable \033[0mfor Staticmap API! Here is the PoC link which can be used directly via browser:")
	print url
	vulnerable_apis.append("Staticmap")
else:
	print "API key is not vulnerable for Staticmap API."
	print "Reason: "+ response.content

url = "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key="+apikey 
response = requests.get(url, verify=False)
if response.status_code == 200:
	print ("\033[1;31;40m API key is \033[1;31;40m vulnerable \033[0m for Streetview API! Here is the PoC link which can be used directly via browser:\033[0m")
	print url
	vulnerable_apis.append("Streetview")
else:
	print "API key is not vulnerable for Streetview API."
	print "Reason: "+ response.content

url = "https://www.google.com/maps/embed/v1/place?q=place_id:ChIJyX7muQw8tokR2Vf5WBBk1iQ&key="+apikey 
response = requests.get(url, verify=False)
if response.status_code == 200:
	print ("\033[1;31;40m API key is \033[1;31;40m vulnerable \033[0m for Embed API! Here is the PoC HTML code which can be used directly via browser:\033[0m")
	print "<iframe width=\"600\" height=\"450\" frameborder=\"0\" style=\"border:0\" src=\""+url+"\" allowfullscreen></iframe>"
	vulnerable_apis.append("Embed")
else:
	print "API key is not vulnerable for Embed API."
	print "Reason: "+ response.content

url = "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key="+apikey
response = requests.get(url, verify=False)
if response.text.find("error_message") < 0:
	print ("\033[1;31;40m API key is \033[1;31;40m vulnerable \033[0m for Directions API! Here is the PoC link which can be used directly via browser:\033[0m")
	print url
	vulnerable_apis.append("Directions")
else:
	print "API key is not vulnerable for Directions API."
	print "Reason: "+ response.json()["error_message"]

url = "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key="+apikey 
response = requests.get(url, verify=False)
if response.text.find("error_message") < 0:
	print ("\033[1;31;40m API key is \033[1;31;40m vulnerable \033[0m for Geocode API! Here is the PoC link which can be used directly via browser:\033[0m")
	print url
	vulnerable_apis.append("Geocode")
else:
	print "API key is not vulnerable for Geocode API."
	print "Reason: "+ response.json()["error_message"]

url = "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key="+apikey 
response = requests.get(url, verify=False)
if response.text.find("error_message") < 0:
	print ("\033[1;31;40m API key is \033[1;31;40m vulnerable \033[0m for Distance Matrix API! Here is the PoC link which can be used directly via browser:\033[0m")
	print url
	vulnerable_apis.append("Distance Matrix")
else:
	print "API key is not vulnerable for Distance Matrix API."
	print "Reason: "+ response.json()["error_message"]

url = "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key="+apikey
response = requests.get(url, verify=False) 
if response.text.find("error_message") < 0:
	print ("\033[1;31;40m API key is vulnerable \033[0m for Find Place From Text API! Here is the PoC link which can be used directly via browser:\033[0m")
	print url
	vulnerable_apis.append("Find Place From Text")
else:
	print "API key is not vulnerable for Find Place From Text API."
	print "Reason: "+ response.json()["error_message"]

url = "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key="+apikey 
response = requests.get(url, verify=False)
if response.text.find("error_message") < 0:
	print ("\033[1;31;40m API key is \033[1;31;40m vulnerable \033[0m for Autocomplete API! Here is the PoC link which can be used directly via browser:\033[0m")
	print url
	vulnerable_apis.append("Autocomplete")
else:
	print "API key is not vulnerable for Autocomplete API."
	print "Reason: "+ response.json()["error_message"]

url = "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key="+apikey 
response = requests.get(url, verify=False)
if response.text.find("error_message") < 0:
	print ("\033[1;31;40m API key is \033[1;31;40m vulnerable \033[0m for Elevation API! Here is the PoC link which can be used directly via browser:\033[0m")
	print url
	vulnerable_apis.append("Elevation")
else:
	print "API key is not vulnerable for Elevation API."
	print "Reason: "+ response.json()["error_message"]

url = "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key="+apikey 
response = requests.get(url, verify=False)
if response.text.find("errorMessage") < 0:
	print ("\033[1;31;40m API key is \033[1;31;40m vulnerable \033[0m for Timezone API! Here is the PoC link which can be used directly via browser:\033[0m")
	print url
	vulnerable_apis.append("Timezone")
else:
	print "API key is not vulnerable for Timezone API."
	print "Reason: "+ response.json()["errorMessage"]

url = "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key="+apikey 
response = requests.get(url, verify=False)
if response.text.find("error") < 0:
	print ("\033[1;31;40m API key is \033[1;31;40m vulnerable \033[0m for Roads API! Here is the PoC link which can be used directly via browser:\033[0m")
	print url
	vulnerable_apis.append("Roads")
else:
	print "API key is not vulnerable for Roads API."
	print "Reason: "+ response.json()["error"]["message"]

url = "https://www.googleapis.com/geolocation/v1/geolocate?key="+apikey 
postdata = {'considerIp': 'true'}
response = requests.post(url, data=postdata, verify=False)
if response.text.find("error") < 0:
	print ("\033[1;31;40m API key is vulnerable \033[0m for Geolocation API! Here is the PoC curl command which can be used from terminal:\033[0m")
	print "curl -i -s -k  -X $'POST' -H $'Host: www.googleapis.com' -H $'Content-Length: 22' --data-binary $'{\"considerIp\": \"true\"}' $'"+url+"'"
	vulnerable_apis.append("Geolocation")
else:
	print "API key is not vulnerable for Geolocation API."
	print "Reason: "+ response.json()["error"]["message"]

print "Because JavaScript API needs manual confirmation from a web browser, tests are not conducted for that API. If the script didn't found any vulnerable endpoints above, to be sure, manual checks can be conducted on this API. For that, go to https://developers.google.com/maps/documentation/javascript/tutorial URL, copy HTML code and change 'key' parameter with the one wanted to test. If loaded without errors on the browser, then it is vulnerable for JavaScript API."
print "Results:"
for i in range (len(vulnerable_apis)):
    print "- " + vulnerable_apis[i]
