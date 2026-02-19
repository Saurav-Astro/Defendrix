class AuthHandler:
    def __init__(self, login_url, username=None, password=None):
        self.login_url = login_url
        self.username = username
        self.password = password

    def authenticate(self, request_manager):
        if not self.login_url or not self.username or not self.password:
            return False
        data = {
            "username": self.username,
            "password": self.password,
        }
        response = request_manager.post(self.login_url, data=data)
        return response is not None and response.status_code < 400
