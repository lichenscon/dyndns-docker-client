import requests
import yaml

def update_provider(provider):
    url = provider['url']
    params = provider['params']
    auth = None
    if 'username' in params and 'password' in params:
        auth = (params.pop('username'), params.pop('password'))
    response = requests.get(url, params=params, auth=auth)
    print(f"{provider['name']} response: {response.text}")

def main():
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    for provider in config['providers']:
        update_provider(provider)

if __name__ == "__main__":
    main()