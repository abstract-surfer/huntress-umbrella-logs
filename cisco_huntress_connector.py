#!/usr/bin/env python
import os
import requests
import time
import json
from datetime import datetime, timedelta, timezone

# --- Environment Variables ---
UMBRELLA_API_KEY = os.environ.get("UMBRELLA_API_KEY")
UMBRELLA_API_SECRET = os.environ.get("UMBRELLA_API_SECRET")
UMBRELLA_ORGANIZATION_ID = os.environ.get("UMBRELLA_ORGANIZATION_ID")
UMBRELLA_MANAGEMENT_API_URL = os.environ.get("UMBRELLA_MANAGEMENT_API_URL", "https://api.umbrella.com/deployments/v2")
UMBRELLA_REPORTS_API_URL = os.environ.get("UMBRELLA_REPORTS_API_URL", "https://reports.api.umbrella.com/v2")
UMBRELLA_AUTH_URL = os.environ.get("UMBRELLA_AUTH_URL", "https://api.umbrella.com/auth/v2/token")
UMBRELLA_CATEGORY_IDS = os.environ.get("UMBRELLA_CATEGORY_IDS") # Optional category filtering

HUNTRESS_HEC_URL = os.environ.get("HUNTRESS_HEC_URL")
HUNTRESS_HEC_TOKEN = os.environ.get("HUNTRESS_HEC_TOKEN")

FETCH_INTERVAL_MINUTES = int(os.environ.get("FETCH_INTERVAL_MINUTES", 60))
IDENTITY_CACHE_REFRESH_MINUTES = int(os.environ.get("IDENTITY_CACHE_REFRESH_MINUTES", 240)) # 4 hours

# --- Debug Mode ---
DEBUG_MODE = os.environ.get("DEBUG_MODE", "false").lower() == "true"

def debug_log(message):
    """Prints a message only if DEBUG_MODE is enabled."""
    if DEBUG_MODE:
        print(f"[DEBUG] {message}")

# --- Log Transformation Logic ---

def _get_labels(data, key='label'):
    """Helper function to extract labels from a list of objects and join them."""
    if not isinstance(data, list):
        return ""
    labels = [str(item.get(key, '')) for item in data if item.get(key)]
    return ", ".join(labels)

def _get_grouped_category_labels(categories_list):
    """
    Groups category labels by their type (e.g., content, application)
    and returns a dictionary of comma-separated label strings.
    """
    grouped_labels = {}
    if not isinstance(categories_list, list):
        return {}

    for category in categories_list:
        cat_type = category.get('type')
        cat_label = category.get('label')

        if cat_type and cat_label:
            key_name = f"{cat_type.capitalize()}Categories"
            if key_name not in grouped_labels:
                grouped_labels[key_name] = []
            grouped_labels[key_name].append(cat_label)

    for key, labels in grouped_labels.items():
        grouped_labels[key] = ", ".join(labels)

    return grouped_labels

def _transform_dns_log(log):
    """Transforms a raw DNS log into a clean, structured object."""
    identity = log.get('identities', [{}])[0]
    identity_label = identity.get('labelResolved', identity.get('label', 'N/A'))

    transformed = {
        "Timestamp": datetime.fromtimestamp(log.get('timestamp', 0) / 1000, tz=timezone.utc).isoformat(),
        "LogType": "dns",
        "IdentityLabel": identity_label,
        "IdentityType": identity.get('type', {}).get('label', 'N/A'),
        "InternalIP": log.get('internalip', ''),
        "ExternalIP": log.get('externalip', ''),
        "Destination": log.get('domain', ''),
        "QueryType": log.get('querytype', ''),
        "Verdict": log.get('verdict', ''),
        "Threats": _get_labels(log.get('threats', []), key='label'),
        "RuleLabel": log.get('rule', {}).get('label', 'N/A'),
        "Source": "Cisco Umbrella",
    }

    grouped_categories = _get_grouped_category_labels(log.get('categories', []))
    transformed.update(grouped_categories)

    applications = _get_labels(log.get('allapplications', []))
    if applications:
        transformed['Applications'] = applications

    return transformed

def _transform_proxy_log(log):
    """Transforms a raw Proxy (Web) log into a clean, structured object."""
    identity_labels = _get_labels(log.get('identities', []))
    identity_types = _get_labels([i.get('type', {}) for i in log.get('identities', [])])

    transformed = {
        "Timestamp": datetime.fromtimestamp(log.get('timestamp', 0) / 1000, tz=timezone.utc).isoformat(),
        "LogType": "proxy",
        "IdentityLabel": identity_labels,
        "IdentityType": identity_types,
        "InternalIP": log.get('internalip', ''),
        "ExternalIP": log.get('externalip', ''),
        "Destination": log.get('url', ''),
        "RequestMethod": log.get('requestmethod', ''),
        "StatusCode": log.get('statuscode', 0),
        "Verdict": log.get('verdict', ''),
        "Threats": _get_labels(log.get('threats', []), key='label'),
        "RuleLabel": log.get('rule', {}).get('label', 'N/A'),
        "Source": "Cisco Umbrella",
    }

    grouped_categories = _get_grouped_category_labels(log.get('categories', []))
    transformed.update(grouped_categories)

    applications = _get_labels(log.get('allapplications', []))
    if applications:
        transformed['Applications'] = applications

    return transformed

def _transform_firewall_log(log):
    """Transforms a raw Firewall log into a clean, structured object."""
    debug_log("Warning: Firewall log transformation not yet implemented. Returning raw log.")
    return log

def transform_log(log):
    """
    Router function to call the correct transformation based on unique keys in the log.
    """
    if 'domain' in log and 'querytype' in log:
        return _transform_dns_log(log)
    elif log.get('type') == 'proxy' and 'url' in log:
        return _transform_proxy_log(log)
    elif 'protocol' in log:
        return _transform_firewall_log(log)
    else:
        debug_log(f"Warning: Unknown log type found. Returning raw log: {log}")
        return log


# --- Core Application Logic ---

def get_umbrella_token():
    """Authenticates to get an OAuth 2.0 access token."""
    print("Requesting new auth token from Cisco Umbrella...")
    try:
        response = requests.post(
            UMBRELLA_AUTH_URL,
            auth=(UMBRELLA_API_KEY, UMBRELLA_API_SECRET),
            data={"grant_type": "client_credentials"}
        )
        response.raise_for_status()
        print("Successfully obtained new auth token.")
        return response.json().get("access_token")
    except requests.exceptions.RequestException as e:
        print(f"Error getting Umbrella API token: {e}")
        return None

def get_identity_mappings(token):
    """Fetches all identities from the Management API to create a mapping cache."""
    if not token: return {}
    print("Fetching identities from Management API to build cache...")
    identity_map = {}
    headers = {"Authorization": f"Bearer {token}"}
    identity_endpoints = {'roamingcomputers': ('originId', 'name')}

    for endpoint, (id_key, label_key) in identity_endpoints.items():
        url = f"{UMBRELLA_MANAGEMENT_API_URL}/{endpoint}"
        try:
            while url:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()
                items = data if isinstance(data, list) else data.get('data', [])
                for item in items:
                    identity_map[str(item[id_key])] = item[label_key]
                url = data.get('meta', {}).get('next') if isinstance(data, dict) else None
        except requests.exceptions.RequestException as e:
            print(f"Error fetching identities from {endpoint}: {e}")
    print(f"Identity cache built with {len(identity_map)} entries.")
    return identity_map

def fetch_from_endpoint(token, endpoint_url, log_type):
    """Generic function to fetch paginated logs from a given Umbrella Reporting API endpoint."""
    if not token: return []
    logs = []
    headers = {"Authorization": f"Bearer {token}"}
    to_time = datetime.now(timezone.utc)
    from_time = to_time - timedelta(minutes=FETCH_INTERVAL_MINUTES)
    params = {"from": int(from_time.timestamp() * 1000), "to": int(to_time.timestamp() * 1000), "limit": 1000}

    # Add optional category filtering if the environment variable is set
    if UMBRELLA_CATEGORY_IDS:
        params['categories'] = UMBRELLA_CATEGORY_IDS
        print(f"Applying category filter with IDs: {UMBRELLA_CATEGORY_IDS}")

    url = f"{UMBRELLA_REPORTS_API_URL}/organizations/{UMBRELLA_ORGANIZATION_ID}{endpoint_url}"

    print(f"Fetching {log_type} logs from {from_time.isoformat()} to {to_time.isoformat()}")
    try:
        page = 1
        while True:
            debug_log(f"Fetching page {page} for {log_type} from URL: {url} with params: {params}")
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            if 'data' in data and data['data']:
                logs.extend(data['data'])

            meta = data.get('meta', {})
            if meta.get('hasMoreData', False) and meta.get('nextPage'):
                url = meta['nextPage']
                params = {}
                page += 1
            else:
                break

    except requests.exceptions.RequestException as e:
        print(f"Error fetching {log_type} logs from Umbrella API: {e}")
    print(f"Found {len(logs)} {log_type} logs in this time window.")
    return logs

def get_dns_logs(token):
    return fetch_from_endpoint(token, "/activity", "DNS")

def get_proxy_logs(token):
    return fetch_from_endpoint(token, "/activity/proxy", "Proxy")

def get_firewall_logs(token):
    return fetch_from_endpoint(token, "/activity/firewall", "Firewall")

def send_to_huntress(logs):
    """Sends a list of transformed logs to the Huntress HEC endpoint."""
    if not logs:
        print("No logs to send to Huntress.")
        return
    headers = {"Authorization": f"Splunk {HUNTRESS_HEC_TOKEN}"}
    payload = ""
    for log in logs:
        event = {
            "event": log,
            "sourcetype": f"cisco:umbrella:{log.get('LogType', 'unknown')}"
        }

        if 'Timestamp' in log and isinstance(log['Timestamp'], str):
            try:
                dt = datetime.fromisoformat(log['Timestamp'])
                event['time'] = dt.timestamp()
            except ValueError:
                debug_log(f"Warning: Could not parse timestamp '{log['Timestamp']}'")

        payload += json.dumps(event) + "\n"

    try:
        response = requests.post(HUNTRESS_HEC_URL, headers=headers, data=payload.encode('utf-8'))
        response.raise_for_status()
        print(f"Successfully sent {len(logs)} logs to Huntress.")
    except requests.exceptions.RequestException as e:
        print(f"Error sending logs to Huntress: {e}")
        if 'response' in locals():
            debug_log(f"Huntress HEC response Body: {response.text}")

def main():
    """Main function to run the log fetching and sending process in a loop."""
    print("Starting Cisco Umbrella to Huntress Connector...")
    required_vars = ["UMBRELLA_API_KEY", "UMBRELLA_API_SECRET", "UMBRELLA_ORGANIZATION_ID", "HUNTRESS_HEC_URL", "HUNTRESS_HEC_TOKEN"]
    if any(not os.environ.get(var) for var in required_vars):
        print(f"Error: Missing one or more required environment variables. Exiting.")
        return

    identity_map, last_cache_refresh = {}, None
    while True:
        to_time_dt, from_time_dt = datetime.now(timezone.utc), datetime.now(timezone.utc) - timedelta(minutes=FETCH_INTERVAL_MINUTES)
        print(f"\n--- Running fetch cycle from {from_time_dt.isoformat()} to {to_time_dt.isoformat()} ---")

        token = get_umbrella_token()
        if token:
            if not last_cache_refresh or (datetime.now() - last_cache_refresh).total_seconds() > IDENTITY_CACHE_REFRESH_MINUTES * 60:
                identity_map = get_identity_mappings(token)
                last_cache_refresh = datetime.now()

            all_logs = []
            all_logs.extend(get_dns_logs(token))
            all_logs.extend(get_proxy_logs(token))
            all_logs.extend(get_firewall_logs(token))

            if all_logs:
                print(f"Total logs fetched from all sources: {len(all_logs)}. Now enriching and transforming...")
                transformed_logs = []
                for log in all_logs:
                    if 'identities' in log and log['identities']:
                        identity_id = str(log['identities'][0].get('id'))
                        if identity_id and identity_id in identity_map:
                            log['identities'][0]['labelResolved'] = identity_map[identity_id]

                    transformed_log = transform_log(log)
                    transformed_logs.append(transformed_log)

                debug_log(f"First transformed log in batch: {json.dumps(transformed_logs[0], indent=2) if transformed_logs else 'None'}")
                send_to_huntress(transformed_logs)
            else:
                print("No logs found from any source in this time window.")

        print(f"--- Cycle complete. Waiting for {FETCH_INTERVAL_MINUTES} minutes before next run. ---")
        time.sleep(FETCH_INTERVAL_MINUTES * 60)

if __name__ == "__main__":
    main()

