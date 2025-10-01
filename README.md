# **Cisco Umbrella to Huntress Generic HEC**

This project provides a Python script, containerized with Docker, to fetch DNS, Proxy (Web), and Firewall logs from the Cisco Umbrella Reporting API v2 and forward them to Huntress using the Generic HTTP Event Collector (HEC).

## **Features**

* Fetches DNS, Proxy, and Firewall logs from the correct Umbrella Reporting API v2 endpoints.
* **Optionally filters** logs by a comma-separated list of category IDs.
* Uses OAuth 2.0 for secure authentication with the Umbrella API.
* Enriches logs by mapping Roaming Client IDs to their human-readable device names.
* Transforms raw, nested JSON logs into a flat, easy-to-read format suitable for HEC ingestion.
* Groups log categories by type (e.g., ContentCategories, ApplicationCategories) for easier parsing in your SIEM.
* Continuously runs on a configurable interval to pull new logs.
* Includes an optional **Debug Mode** for verbose logging, toggleable via an environment variable.

## **Prerequisites**

* Docker installed and running on your system.
* Git installed on your system.
* A Cisco Umbrella API Key and API Secret.
* Your Cisco Umbrella Organization ID.
* A Huntress account with a Generic HEC source configured.
* The HEC Token provided by your Huntress HEC source.

## **Configuration for GitHub**

This repository is designed to be safe for public hosting. Your secrets are managed in a .env file, which is explicitly ignored by Git via the .gitignore file and should never be committed.

## **Documentation**

* [Cisco Umbrella API Documentation](https://developer.cisco.com/docs/cloud-security/umbrella-api-reference-reports-overview/)
* [Huntress Generic HEC Documentation](https://support.huntress.io/hc/en-us/articles/36169678734867-Collecting-HEC-HTTP-Event-Collector-Sources)

## **Setup Steps**

1. **Clone the Repository (if you haven't already):**
   ```
   git clone \[https://github.com/abstract-surfer/huntress-umbrella-logs\](https://github.com/abstract-surfer/huntress-umbrella-logs)
   ```

2. Create your local .env file:
   Copy the provided .env.example template to create your local environment file.
   `cp .env.example .env`

3. Edit the .env file:
   Open the newly created .env file and fill in your actual secrets and configuration values.

| Environment Variable | Description |
| :---- | :---- |
| UMBRELLA_API_KEY | **Required.** Your API key for the Cisco Umbrella API. |
| UMBRELLA_API_SECRET | **Required.** Your API secret for the Cisco Umbrella API. |
| UMBRELLA_ORGANIZATION_ID | **Required.** Your numeric Organization ID from the Umbrella dashboard. |
| HUNTRESS_HEC_URL | **Required.** The full URL for your Huntress Generic HEC endpoint. |
| HUNTRESS_HEC_TOKEN | **Required.** The HEC token from your Huntress Generic HEC setup. |
| UMBRELLA_CATEGORY_IDS | **Optional.** A comma-separated list of numeric category IDs to fetch. If omitted, all logs are fetched. See [Category Reference](UMBRELLA_CATEGORIES.md) for a complete list. |
| FETCH_INTERVAL_MINUTES | The interval in minutes to wait between fetching logs. Defaults to 60. |
| DEBUG_MODE | Optional. Set to true to enable verbose logging for troubleshooting. Defaults to false. |

**Important:** Your Umbrella API Key must have the following scopes:

* reports (for reading reports)
* admin:read or deployments (for reading roaming client identities)

## **How to Run**

1. Build the Docker Image:
   From the root of the project directory, run the following command:
   `docker build -t umbrella-huntress-connector .`

2. Run the Docker Container:
   Use the docker run command with the --env-file flag to start the container in the background.
   ```
   docker run --rm -d --env-file ./.env --name umbrella-huntress-instance umbrella-huntress-connector
   ```

   * --rm: Automatically removes the container when it stops.
   * -d: Runs the container in detached (background) mode.
   * --env-file ./.env: Loads your environment variables from the .env file.
   * --name umbrella-huntress-instance: Assigns a memorable name to the container.

## **Troubleshooting**

For debugging, it's best to run the container interactively to see the output directly.
```
docker run --rm -it --env-file ./.env --name umbrella-huntress-instance umbrella-huntress-connector /bin/bash
```

Once inside the container's shell, you can run the script manually:

`python .cisco_splunk_connector.py`

## **Viewing Logs**

To see the output of the running container and check for any errors, you can view the container's logs:

\# Follow the logs in real-time
`docker logs -f umbrella-huntress-instance`

## **Stopping the Container**

To stop the container, use the docker stop command with the name you assigned:

`docker stop umbrella-huntress-instance`