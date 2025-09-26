# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app/

# Make the script executable
RUN chmod +x cisco_splunk_connector.py

# Install any needed packages specified in requirements.txt (if you had one)
# For this script, the requests library is needed.
RUN pip install requests

# Define the command to run the script
CMD ["python", "cisco_splunk_connector.py"]

