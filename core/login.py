import requests
import json
import base64
import sys
from utils.config import update_value, get_value
import utils.logs as logs
from . import zapscan, parsers

class APILogin:
    def __init__(self):
        self.api_logger = zapscan.logger()
        self.parse_data = parsers.PostmanParser()

    def fetch_logintoken(self, url, method, headers, body=None, relogin=None):
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, json=body)
                logs.logging.info("HTTP response of login API: %s", response.status_code)
            else:
                raise ValueError("Invalid HTTP method")

            response_data = response.json()
            return self.handle_authentication(response, response_data, url)
        
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            logs.logging.error(f"Error during login request: {e}")
            sys.exit(1)

    def handle_authentication(self, response, response_data, url):
        auth_type = get_value('config.property', 'login', 'auth_type')
        auth_names = get_value('config.property', 'login', 'auth_names').split(',')
        
        if auth_type == 'cookie' and 'Set-Cookie' in response.headers:
            auth_cookie = {'cookie': response.headers['Set-Cookie']}
            update_value('login', 'cookie', auth_cookie)
            update_value('login', 'auth_success', 'Y')
            logs.logging.info("[+] Login successful via cookie.")
            return True
        else:
            for auth_name in auth_names:
                if auth_name in response_data:
                    auth_token = response_data[auth_name]
                    update_value('login', 'auth_success', 'Y')
                    update_value('login', 'auth_success_param', auth_name)
                    update_value('login', 'auth_success_token', auth_token)
                    logs.logging.info("[+] Login successful via token.")
                    return True
        logs.logging.error("Login failed.")
        return False

    def auth_verify(self, collection_data, api):
        url_list = self.create_urllist(collection_data)
        api_types = ['login', 'signin', 'authenticate'] if api == 'login' else ['logout', 'signout']
        
        for url in url_list:
            if any(name in url for name in api_types):
                result = input(f"Is {api.capitalize()} URL correct? (y/n): {url} ")
                if result.lower() == 'y':
                    return url, api
        return None, None
