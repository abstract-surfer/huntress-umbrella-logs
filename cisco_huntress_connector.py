#!/usr/bin/env python3
import os
import requests
import json
import time
from datetime import datetime, timedelta

# --- Configuration from Environment Variables ---
# Cisco Umbrella API Configuration
UMBRELLA_API_KEY = os.environ.get("UMBRELLA_API_KEY")
UMBRELLA_API_SECRET = os.environ.get("UMBRELLA_API_SECRET")
UMBRELLA_ORGANIZATION_ID = os.environ.get("UMBRELLA_ORGANIZATION_ID")
UMBRELLA_AUTH_URL = os.environ.get("UMBRELLA_AUTH_URL", "https://api.umbrella.com/auth/v2/token")
UMBRELLA_API_URL = os.environ.get("UMBRELLA_API_URL", "https://reports.api.umbrella.com/v2") 
UMBRELLA_CATEGORY_IDS = os.environ.get("UMBRELLA_CATEGORY_IDS")

# Splunk HEC Configuration
SPLUNK_HEC_URL = os.environ.get("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN")

# Script Configuration
FETCH_INTERVAL_MINUTES = int(os.environ.get("FETCH_INTERVAL_MINUTES", 60))


def get_umbrella_auth_token():
    """
    Retrieves an OAuth 2.0 access token from the Cisco Umbrella API using the
    client credentials grant type.
    """
    if not all([UMBRELLA_API_KEY, UMBRELLA_API_SECRET]):
        print("Error: UMBRELLA_API_KEY or UMBRELLA_API_SECRET environment variables are not set.")
        return None
    
    try:
        print("Requesting new auth token from Cisco Umbrella...")
        response = requests.post(
            UMBRELLA_AUTH_URL,
            auth=(UMBRELLA_API_KEY, UMBRELLA_API_SECRET),
            data={'grant_type': 'client_credentials'}
        )
        response.raise_for_status()
        token = response.json().get('access_token')
        print("Successfully obtained new auth token.")
        return token
    except requests.exceptions.RequestException as e:
        print(f"Error obtaining Umbrella auth token: {e}")
        if 'response' in locals():
            print(f"Response Body: {response.text}")
        return None


def get_umbrella_logs(auth_token, category_ids, from_time, to_time):
    """
    Fetches logs from the Cisco Umbrella API v2 for a specific organization, 
    category IDs and time range using a provided bearer token.
    """
    if not all([auth_token, UMBRELLA_ORGANIZATION_ID]):
        print("Error: Auth token or Organization ID is missing.")
        return None

    headers = {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }
    
    url = f"{UMBRELLA_API_URL.rstrip('/')}/organizations/{UMBRELLA_ORGANIZATION_ID}/activity"
    
    all_logs = []
    page = 1
    limit = 1000 # Max limit per page

    while True:
        params = {
            'from': from_time,
            'to': to_time,
            'limit': limit,
            'page': page,
            'categoryids': category_ids
        }
        
        try:
            print(f"Fetching page {page} for category IDs '{category_ids}'...")
            print(f"Requesting URL: {url}")
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            
            data = response.json().get('data', [])
            
            if not data:
                print(f"No more data found for this time range.")
                break
                
            all_logs.extend(data)
            
            if len(data) < limit:
                break
                
            page += 1
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching logs from Umbrella API: {e}")
            if 'response' in locals():
                 print(f"Response Body: {response.text}")
            return None
            
    return all_logs


def send_to_splunk(logs):
    """
    Sends a list of log events to the Splunk HTTP Event Collector.
    """
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        print("Error: Splunk HEC URL or Token environment variables not set.")
        return False

    headers = {
        'Authorization': f'Splunk {SPLUNK_HEC_TOKEN}'
    }
    
    payload = ""
    for log in logs:
        event = {"event": log, "sourcetype": "cisco:umbrella"}
        payload += json.dumps(event)

    try:
        response = requests.post(SPLUNK_HEC_URL, headers=headers, data=payload, verify=True)
        response.raise_for_status()
        print(f"Successfully sent {len(logs)} events to Splunk.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error sending logs to Splunk: {e}")
        print(f"Response Body: {response.text if 'response' in locals() else 'No response'}")
        return False

def main():
    """
    Main function to orchestrate fetching logs and sending them to Splunk.
    """
    print("Starting Cisco Umbrella to Splunk log collection script (using OAuth 2.0).")

    required_vars = [
        "UMBRELLA_API_KEY", "UMBRELLA_API_SECRET", "UMBRELLA_ORGANIZATION_ID", 
        "UMBRELLA_CATEGORY_IDS", "SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN"
    ]
    if not all(os.environ.get(var) for var in required_vars):
        print("One or more required environment variables are missing. Please check your .env file. Exiting.")
        return

    while True:
        # Get a fresh auth token for each cycle to avoid expiration
        auth_token = get_umbrella_auth_token()
        
        if not auth_token:
            print(f"Could not retrieve auth token. Retrying in {FETCH_INTERVAL_MINUTES} minutes.")
            time.sleep(FETCH_INTERVAL_MINUTES * 60)
            continue

        to_time = int(time.time() * 1000)
        from_time = to_time - (FETCH_INTERVAL_MINUTES * 60 * 1000)
        
        print(f"\n--- Running fetch cycle from {datetime.fromtimestamp(from_time/1000)} to {datetime.fromtimestamp(to_time/1000)} ---")

        logs = get_umbrella_logs(auth_token, UMBRELLA_CATEGORY_IDS, from_time, to_time)

        if logs:
            print(f"Found {len(logs)} log events for the specified categories.")
            send_to_splunk(logs)
        else:
            print(f"No logs found for the specified categories in this time window.")
        
        print(f"--- Cycle complete. Waiting for {FETCH_INTERVAL_MINUTES} minutes before next run. ---")
        time.sleep(FETCH_INTERVAL_MINUTES * 60)


if __name__ == "__main__":
    main()

