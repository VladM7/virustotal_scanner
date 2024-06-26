import sys
import requests
import sched, time
import logging
import argparse
import os
from dotenv import load_dotenv

# If the scan is queued, check for results every check_interval seconds
check_interval = 10

# If no file path is provided, save the results to scan_results.json
output_file_path = "scan_results.json"

load_dotenv()

url = "https://www.virustotal.com/api/v3/files"

headers = {
    "accept": "application/json",
    "x-apikey": os.getenv("API_KEY"),
}

# Create the parser
parser = argparse.ArgumentParser(
    description="Application to scan files with VirusTotal API, accessible via CLI."
)

# Add arguments
parser.add_argument(
    "--input",
    type=str,
    required=True,
    help="path to the file to scan or id of the request to check",
)
parser.add_argument(
    "--output",
    type=str,
    required=False,
    help="output file path for scan results; it defaults to scan_results.json",
)
parser.add_argument(
    "--check-request", action="store_true", help="check the status of a previous scan"
)
parser.add_argument(
    "--no-output", action="store_true", help="do not save the scan results to a file"
)

# Parse the arguments
args = parser.parse_args()


def safe_request(url, headers):
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises HTTPError for bad responses
        return response
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        os._exit(1)


def write_response_to_file(response):
    if args.no_output:
        return
    with open(output_file_path, "w") as file:
        file.write(response.text)


logging.basicConfig(level=logging.INFO, format="%(message)s")


def print_results(file_request, output_file_path):
    try:
        request_id = file_request["data"]["id"]
        stats = file_request["data"]["attributes"]["stats"]
        logging.info(f"Scan status: completed. Results for request {request_id}:")

        for stat, value in stats.items():
            logging.info(f"    {stat}: {value}")

        if args.no_output:
            os._exit(0)
        logging.info(f"Full scan results saved to {output_file_path}")
    except KeyError as e:
        logging.error(f"Missing key in file_request: {e}")
    os._exit(0)


def check_for_results(analysis_url, output_file_path, scheduler):
    scheduler.enter(
        check_interval,
        1,
        check_for_results,
        (analysis_url, output_file_path, scheduler),
    )

    analysis_response = safe_request(analysis_url, headers)
    analysis_request = analysis_response.json()

    if analysis_request["data"]["attributes"]["status"] == "completed":
        write_response_to_file(analysis_response)
        print_results(analysis_request, output_file_path)


def analyze_file(analysis_id):
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    analysis_response = safe_request(analysis_url, headers)
    analysis_request = analysis_response.json()

    write_response_to_file(analysis_response)

    if analysis_request["data"]["attributes"]["status"] == "queued":
        print("Scan status: queued. Please wait...")
        my_scheduler = sched.scheduler(time.time, time.sleep)
        my_scheduler.enter(
            check_interval,
            1,
            check_for_results,
            (analysis_url, output_file_path, my_scheduler),
        )
        my_scheduler.run()
    else:
        write_response_to_file(analysis_response)
        print_results(analysis_request, output_file_path)


def scan_file(filename):
    files = {"file": (filename, open(filename, "rb"), "application/octet-stream")}
    response = requests.post(url, files=files, headers=headers)

    # print(response.text)

    if response.status_code == 200:
        file_request = response.json()
        analysis_id = file_request["data"]["id"]
        analyze_file(analysis_id)
    else:
        raise Exception("Bad response ({response.status_code})")


if args.output:
    output_file_path = args.output

if args.check_request:
    analyze_file(args.input)
else:
    scan_file(args.input)
