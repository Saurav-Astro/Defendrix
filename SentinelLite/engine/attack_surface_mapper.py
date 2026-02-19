from urllib.parse import urlparse, parse_qs


class AttackSurfaceMapper:
    def map(self, endpoints, forms, parameters):
        input_vectors = sum(len(form.get("inputs", [])) for form in forms)
        return {
            "endpoints": len(endpoints),
            "forms": len(forms),
            "parameters": len(parameters),
            "input_vectors": input_vectors,
        }
