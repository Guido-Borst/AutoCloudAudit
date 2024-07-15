# Copyright (c) 2024 Guido Borst
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import webbrowser
import requests
import json
import configparser
import os

# Colors for the terminal
GREEN = '\033[92m'
YELLOW = '\033[93m'
ORANGE = '\033[38;5;208m'
RED = '\033[91m'
BOLD = '\033[1m'
NC = '\033[0m'

# Not used by the script, but useful for reference/future extensions
def get_oauth_tokens_device_code(client_id="12345678-123a-12ac-1234-1234abcd1234", print=False):

    # Open authorization URL in browser
    authorization_url = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={client_id}&scope=openid%20profile%20https://ads.microsoft.com/msads.manage%20offline_access&response_type=code&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient&state=ClientStateGoesHere&prompt=login"
    webbrowser.open(authorization_url)

    # Prompt user for code from response URI
    code = input("Grant consent in the browser, and then enter the response URI here: ")
    code = code.split("=")[1].split("&")[0]  # Extract code from URI

    # Get initial access and refresh tokens
    token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "scope": "https://ads.microsoft.com/msads.manage offline_access",
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": "https://login.microsoftonline.com/common/oauth2/nativeclient",
    }

    response = requests.post(token_url, data=data)
    oauth_tokens = response.json()

    access_token = oauth_tokens["access_token"]
    expires_in = oauth_tokens["expires_in"]
    refresh_token = oauth_tokens["refresh_token"]

    tokens = {
        "access_token": access_token,
        "expires_in": expires_in,
        "refresh_token": refresh_token
    }

    if print:
        print("Access token:", access_token)
        print("Access token expires in:", expires_in)
        print("Refresh token:", refresh_token)

    return tokens


# Returns the access ID and key for the given AWS profile
def get_aws_credentials(profile='default'):
    # AWS creds are stored in ~/.aws/credentials
    try:
        config = configparser.ConfigParser()
        config.read(os.path.expanduser('~/.aws/credentials'))
        credentials = {
            'aws_access_key_id': config.get(profile, 'aws_access_key_id'),
            'aws_secret_access_key': config.get(profile, 'aws_secret_access_key')
        }
        return credentials
    except Exception as e:
        print(f"Error getting AWS credentials: {e}")
        return None

# Returns the key components of the Azure credentials
def get_azure_credentials(profile='default'):
    # Creds are stored in ~/.azure/msal_token_cache.json and ~/.azure/azureProfile.json
    try:
        with open(os.path.expanduser('~/.azure/msal_token_cache.json'), 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        # Extract the first available IdToken and RefreshToken
        idtoken_key = next(iter(data.get('IdToken', {})), None)
        if idtoken_key:
            idtoken = data['IdToken'][idtoken_key]
        else:
            print("No IdToken found")
            return None
        refreshtoken_key = next(iter(data.get('RefreshToken', {})), None)
        if refreshtoken_key:
            refreshtoken = data['RefreshToken'][refreshtoken_key]
        else:
            print("No RefreshToken found")
            return None

        # Extract the AccessToken for graph.microsoft.com
        accesstoken_key = next((key for key in data.get('AccessToken', {}) if 'graph.windows.net' in key), None)
        if accesstoken_key:
            accesstoken = data['AccessToken'][accesstoken_key]
        else:
            print(f"{RED}{BOLD}No AccessToken for graph.windows.net found, tryng to continue anyway{NC}")

        # Extract the selected profile/subscription, if not given use the first one
        with open(os.path.expanduser('~/.azure/azureProfile.json'), 'r', encoding='utf-8-sig') as f:
            profile = json.load(f)

        subscription = profile.get('subscriptions', [{}])[0]
        if profile != '' and profile != 'default':
            for sub in profile.get('subscriptions', []):
                if f"{sub.get('name', '')} ({sub.get('id', '')})" == profile:
                    subscription = sub
                    break
        
        # Build the credentials dictionary
        credentials = {
            'id_token': idtoken.get('secret', ''),
            'home_account_id': idtoken.get('home_account_id', ''),
            'client_id': idtoken.get('client_id', ''),
            'refresh_token': refreshtoken.get('secret', ''),
            'access_token': accesstoken.get('secret', ''),
            'subscription_id': subscription.get('id', ''),
            'subscription_name': subscription.get('name', ''),
            'directory_id': subscription.get('tenantId', ''),
            'subscriptions': profile.get('subscriptions', [])
        }
        return credentials
    except Exception as e:
        print(f"Error getting Azure credentials: {e}")
        return None

# Returns the list of AWS profiles
def list_aws_profiles():
    try:
        config = configparser.ConfigParser()
        config.read(os.path.expanduser('~/.aws/credentials'))
        profiles = config.sections()
        return profiles
    except Exception as e:
        print(f"Error listing AWS profiles: {e}")
        return []

# Returns the list of Azure profiles
def list_azure_profiles():
    try:
        with open(os.path.expanduser('~/.azure/azureProfile.json'), 'r', encoding='utf-8-sig') as f:
            profile = json.load(f)
        subscriptions = profile.get('subscriptions', [])
        return [f"{sub.get('name', '')} ({sub.get('id', '')})" for sub in subscriptions]
    except Exception as e:
        print(f"Error listing Azure profiles: {e}")
        return []

# Returns True if the user is logged in to the given provider
def check_logged_in_cli(provider, profile='default'):
    credentials = get_aws_credentials(profile) if provider == 'aws' else get_azure_credentials() if provider == 'azure' else None
    if credentials is None:
        return False

    if provider == 'aws':
        return all(credentials.get(key) for key in ['aws_access_key_id', 'aws_secret_access_key'])
    elif provider == 'azure':
        return all(credentials.get(key) for key in ['id_token', 'home_account_id', 'client_id', 'refresh_token'])

    return False


# Create a CloudSploit config file with the given credentials
def create_cloudsploit_config(provider, credentials):
    try:
        config_path = os.path.abspath(os.path.join(os.getcwd(),'tools', 'cloudsploit', 'creds.json'))
        config = {}

        if provider.lower() == 'aws':
            config = {
                "accessKeyId": credentials.get('aws_access_key_id'),
                "secretAccessKey": credentials.get('aws_secret_access_key')
            }
        elif provider.lower() == 'azure':
            config = {
                # "ApplicationID": "APP_ID_HERE",
                # "KeyValue": "KEY_VALUE_HERE",
                "ApplicationID": credentials.get('application_id'),
                "KeyValue": credentials.get('key_value'),
                "DirectoryID": credentials.get('directory_id'),
                "SubscriptionID": credentials.get('subscription_id'),
            }

        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        print(f"Error creating CloudSploit config: {e}")
        return False



print(f"Logged into AWS: {check_logged_in_cli('aws', )}")
print(f"Logged into Azure: {check_logged_in_cli('azure')}")



