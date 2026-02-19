from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class MutationEngine:
    def generate_mutations(self, url, payloads):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            params = {"test": [""]}

        mutations = []
        for key in params:
            for payload in payloads:
                mutated_params = {param: list(values) for param, values in params.items()}
                mutated_params[key] = [payload]
                query_string = urlencode(mutated_params, doseq=True)
                mutated_url = urlunparse(parsed._replace(query=query_string))
                mutations.append({
                    "param": key,
                    "payload": payload,
                    "url": mutated_url,
                })

        return mutations
