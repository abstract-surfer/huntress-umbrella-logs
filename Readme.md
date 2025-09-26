# **Cisco Umbrella to Huntress Generic HEC**

This project provides a simple Python script, containerized with Docker, to fetch security logs from the Cisco Umbrella Reporting API v2 and forward them to a Huntress using the Generic HTTP Event Collector (HEC).

## **Features**

* Authenticates with the Cisco Umbrella API using the OAuth 2.0 Client Credentials flow.  
* Fetches logs from specified Cisco Umbrella category IDs.  
* Sends logs to Huntress Generic HEC in the correct format.  
* Configurable through environment variables for easy deployment and security.  
* Containerized for portability and consistent execution.  
* Runs on a configurable schedule to periodically pull new logs.

## **Prerequisites**

* Docker installed and running on your system.  
* Git installed on your system.  
* A Cisco Umbrella API Key and API Secret.  
* Your Cisco Umbrella Organization ID.  
* A Huntress SIEM instance with a Generic HEC source created.
* The Generic HEC Token created in your Huntress SIEM Source Management page.

## **Configuration for GitHub**

This repository is designed to be safe for public hosting. Your secrets are managed in a .env file, which is explicitly ignored by Git via the .gitignore file and should never be committed.

**Setup Steps:**

1. Clone the Repository (if applicable):  
   git clone \<your-repo-url\>  
2. Create your local .env file:  
   Copy the provided template to create your local environment file.  
   cp .env.example .env

3. Edit the .env file:  
   Open the newly created .env file and fill in your actual secrets and configuration values.

| Environment Variable | Description |
| :---- | :---- |
| UMBRELLA\_API\_KEY | **Required.** Your API key for the Cisco Umbrella API. |
| UMBRELLA\_API\_SECRET | **Required.** Your API secret for the Cisco Umbrella API. |
| UMBRELLA\_ORGANIZATION\_ID | **Required.** Your numeric Organization ID from the Umbrella dashboard. |
| UMBRELLA\_API\_URL | The base URL for the Umbrella API. Defaults to the v2 reports API. |
| UMBRELLA\_CATEGORY\_IDS | **Required.** A comma-separated list of numeric security category IDs to fetch. |
| HUNTRESS\_HEC\_URL | **Required.** The full URL for your Huntress Generic HEC endpoint. |
| HUNTRESS\_HEC\_TOKEN | **Required.** The HEC token from your Huntress Generic HEC setup. |
| FETCH\_INTERVAL\_MINUTES | The interval in minutes to wait between fetching logs. Defaults to 60. |

## **How to Run**

1. Build the Docker Image:  
   Open a terminal in the project directory and run the following command to ensure you get the latest changes:  
   docker build \--no-cache \-t cisco-huntress-connector .

2. Run the Docker Container:  
   Use the docker run command with the \--env-file flag to start the container. For debugging, it's best to run it interactively first.  
   docker run \--rm \-it \--env-file ./.env \--name cisco-huntress-connector-instance cisco-huntress-connector /bin/bash

   Once inside, you can run the script manually: python ./cisco\_huntress\_connector.py

## **Viewing Logs**

To see the output of the running script and check for any errors, you can view the container's logs:

docker logs \-f cisco-huntress-connector-instance

## **Stopping the Container**

To stop the container, use the docker stop command with the name you assigned:

docker stop cisco-huntress-connector-instance  