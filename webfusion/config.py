"""Central configuration and paths."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("WEBFUSION_DATA", os.path.join(BASE_DIR, "webfusion_data"))
DB_PATH = os.path.join(DATA_DIR, "history.db")

# Web UI / API server
API_HOST = os.environ.get("WEBFUSION_API_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("WEBFUSION_API_PORT", "8777"))

# Intercepting proxy
PROXY_HOST = os.environ.get("WEBFUSION_PROXY_HOST", "127.0.0.1")
DEFAULT_PROXY_PORT = int(os.environ.get("WEBFUSION_PROXY_PORT", "8080"))

# Where mitmproxy writes its CA certificate (default location)
CONFDIR = os.path.expanduser("~/.mitmproxy")
CA_CERT_PATH = os.path.join(CONFDIR, "mitmproxy-ca-cert.pem")

os.makedirs(DATA_DIR, exist_ok=True)
