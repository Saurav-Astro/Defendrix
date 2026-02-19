from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def inject_parameter(url, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    
    if params:
        first_param = list(params.keys())[0]
        params[first_param] = [payload]
    else:
        params['test'] = [payload]
    
    query_string = urlencode(params, doseq=True)
    new_parsed = parsed._replace(query=query_string)
    
    return urlunparse(new_parsed)


def parse_query_params(url):
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def rebuild_url(base_url, params):
    parsed = urlparse(base_url)
    query_string = urlencode(params, doseq=True)
    new_parsed = parsed._replace(query=query_string)
    return urlunparse(new_parsed)
