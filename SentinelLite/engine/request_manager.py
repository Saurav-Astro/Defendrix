import requests
from urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class RequestManager:
    def __init__(self, timeout=5, verify=False, session=None):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.verify = verify

    def get(self, url, params=None):
        try:
            return self.session.get(url, params=params, timeout=self.timeout, verify=self.verify, allow_redirects=True)
        except requests.RequestException:
            return None
        except Exception:
            return None

    def post(self, url, data=None):
        try:
            return self.session.post(url, data=data or {}, timeout=self.timeout, verify=self.verify, allow_redirects=True)
        except requests.RequestException:
            return None
        except Exception:
            return None
