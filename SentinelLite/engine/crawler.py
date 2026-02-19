from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

from bs4 import BeautifulSoup


class Crawler:
    def __init__(self, session, base_url, max_depth=2):
        self.session = session
        self.base_url = self._normalize_url(base_url)
        self.max_depth = max_depth
        self.visited = set()
        self.endpoints = set()
        self.forms = []
        self.parameters = set()

    def crawl(self):
        self._crawl_recursive(self.base_url, 0)
        return {
            "endpoints": sorted(self.endpoints),
            "forms": self.forms,
            "parameters": sorted(self.parameters),
        }

    def _crawl_recursive(self, url, depth):
        if depth > self.max_depth or url in self.visited:
            return
        self.visited.add(url)

        response = self._fetch(url)
        if not response:
            return

        self.endpoints.add(url)
        self._extract_params(url)
        self._extract_links(response, url, depth)
        self._extract_forms(response, url)

    def _fetch(self, url):
        try:
            return self.session.get(url, timeout=5, verify=False, allow_redirects=True)
        except Exception:
            return None

    def _extract_links(self, response, current_url, depth):
        soup = BeautifulSoup(response.text or "", "html.parser")
        for link in soup.find_all("a", href=True):
            href = link.get("href", "").strip()
            if not href or href.startswith("mailto:") or href.startswith("javascript:"):
                continue
            next_url = self._normalize_url(urljoin(current_url, href))
            if self._same_domain(next_url):
                self._crawl_recursive(next_url, depth + 1)

    def _extract_forms(self, response, current_url):
        soup = BeautifulSoup(response.text or "", "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method") or "GET").upper()
            action_url = self._normalize_url(urljoin(current_url, action))
            if not self._same_domain(action_url):
                continue
            inputs = []
            for input_field in form.find_all(["input", "textarea", "select"]):
                name = input_field.get("name")
                if name:
                    inputs.append(name)
            self.forms.append({
                "action": action_url,
                "method": method,
                "inputs": inputs,
            })
            self._extract_params(action_url)

    def _extract_params(self, url):
        parsed = urlparse(url)
        for param in parse_qs(parsed.query, keep_blank_values=True):
            self.parameters.add(param)

    def _same_domain(self, url):
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def _normalize_url(self, url):
        parsed = urlparse(url)
        normalized = parsed._replace(fragment="")
        return urlunparse(normalized)
