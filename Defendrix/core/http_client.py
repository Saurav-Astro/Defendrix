import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def fetch_url(url, timeout=5):
    try:
        response = requests.get(url, timeout=timeout, verify=False)
        return response
    except requests.exceptions.RequestException:
        return None
    except Exception:
        return None
