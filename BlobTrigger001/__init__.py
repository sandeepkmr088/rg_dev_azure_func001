import os
import json
from datetime import datetime
from urllib.parse import urlparse
import tarfile
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.durable_functions import DurableOrchestrationClient
from concurrent.futures import ThreadPoolExecutor, as_completed

# Helper Functions
def parse_blob_url(blob_url):
    parsed_url = urlparse(blob_url)
    path_segments = parsed_url.path.split("/")
    container = path_segments[1] if len(path_segments) > 1 else ""
    prefix = "/".join(path_segments[2:]) if len(path_segments) > 2 else ""
    print(f"Parsed blob URL. Container: {container}, Prefix: {prefix}")
    return container, prefix

def parse_file_name(elements):
    part_no = None
    marker_file_name = "_SUCCESS"
    
    # Check that there are enough elements
    if len(elements) < 3:
        print("Error: Path elements are insufficient:", elements)
        raise IndexError("Path does not contain enough elements to parse file name details.")
    
    # Determine part number and build marker file name
    if 'part' in elements[-2]:
        part_no = elements[-1]
        marker_file_name += f"_PART_{part_no.upper()}"
        
    try:
        # Safely extract identifiers
        sbom_id = elements[-3 if part_no else -2]
        project_id = elements[-4 if part_no else -3]
        tenant_id = elements[-5 if part_no else -4]
    except IndexError as e:
        print(f"Error while parsing file name elements: {e}")
        raise
    
    print(f"Parsed file name details. Tenant ID: {tenant_id}, Project ID: {project_id}, SBOM ID: {sbom_id}, Part No: {part_no}")
    return part_no, marker_file_name, sbom_id, project_id, tenant_id

def blob_exists(blob_service_client, container, blob_path):
    blob_client = blob_service_client.get_blob_client(container, blob_path)
    return blob_client.exists()

def download_blob_to_temp(blob_service_client, container, blob_path, file_name, temp_dir):
    local_file_path = os.path.join(temp_dir, file_name)
    blob_client = blob_service_client.get_blob_client(container, blob_path)
    with open(local_file_path, "wb") as f:
        f.write(blob_client.download_blob().readall())
    print(f"Downloaded blob to {local_file_path}")

def unarchive_tarball(gzip_file_name, extraction_dir_name, temp_dir):
    gzip_file_path = os.path.join(temp_dir, gzip_file_name)
    extraction_dir = os.path.join(temp_dir, extraction_dir_name)
    with tarfile.open(gzip_file_path) as tar:
        tar.extractall(extraction_dir)
    print(f"Extracted {gzip_file_name} to {extraction_dir}")

def upload_in_parallel(blob_service_client, container, temp_dir, extraction_dir_name, blob_prefix):
    extraction_dir = os.path.join(temp_dir, extraction_dir_name)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for subdir, _, files in os.walk(extraction_dir):
            for file_name in files:
                local_path = os.path.join(subdir, file_name)
                blob_path = f"{blob_prefix}/{os.path.relpath(local_path, extraction_dir)}"
                futures.append(executor.submit(upload_blob, blob_service_client, container, local_path, blob_path))
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Exception during parallel upload: {e}")

def upload_blob(blob_service_client, container, local_path, blob_path):
    blob_client = blob_service_client.get_blob_client(container, blob_path)
    with open(local_path, "rb") as data:
        blob_client.upload_blob(data, overwrite=True)
    print(f"Uploaded {local_path} to {blob_path}")

# Main Function
def main(blob: func.InputStream):
    print(f"Blob trigger function processed blob\n"
          f"Name: {blob.name}\n"
          f"Blob Size: {blob.length} bytes")

    # Initialize clients and environment configurations.
    blob_service_client = BlobServiceClient(account_url=os.environ["AzureWebJobsStorage"],
                                            credential=DefaultAzureCredential())
    #durable_client = DurableOrchestrationClient()

    # Parse blob trigger path.
    src_container, prefix = parse_blob_url(blob.uri)

    # Extract environment variables.
    oss_tenant_id = os.getenv('OssTenantId')
    dest_container = os.getenv('DestinationContainer')
    state_machine_arn = os.getenv('StateMachineArn')

    # Parse and validate file name details.
    gzip_file_name = os.path.basename(prefix)
    extraction_dir_name = os.path.splitext(os.path.splitext(gzip_file_name)[0])[0]
    elements = extraction_dir_name.split('-')
    
    try:
        part_no, marker_file_name, sbom_id, project_id, tenant_id = parse_file_name(elements)
    except IndexError as e:
        print("Failed to parse file name details:", e)
        return None  # Explicitly returning None to avoid return issues.

    # Check if this tarball has already been processed.
    marker_exists = blob_exists(blob_service_client, src_container, f"{os.path.dirname(prefix)}/{marker_file_name}")
    if marker_exists:
        print(f"Skipping processing as {marker_file_name} marker is present.")
        return None

    # Verify tenant and select state machine for triggering.
    is_tc_mode = tenant_id == oss_tenant_id
    state_machine_arn = os.getenv('StateMachineArn') if is_tc_mode else os.getenv('StateMachineArnFasttrack')

    # Download, extract, and reorganize files.
    temp_dir = "/tmp"
    download_blob_to_temp(blob_service_client, src_container, prefix, gzip_file_name, temp_dir)
    unarchive_tarball(gzip_file_name, extraction_dir_name, temp_dir)
    
    # Upload extracted files in parallel to destination container.
    blob_unarchived_path = f"var/lineaje/data/veeCLI/{tenant_id}/{project_id}/{sbom_id}/"
    if part_no:
        blob_unarchived_path += f"{part_no}/"
    upload_in_parallel(blob_service_client, dest_container, temp_dir, extraction_dir_name, blob_unarchived_path)

    # Trigger the durable function.
    run_date = datetime.now().strftime("%Y%m%d%H%M")
    sf_input = {
        "transformationJobParameters": [
            f"blob://{dest_container}/{blob_unarchived_path}",
            f"blob://{dest_container}/var/lineaje/data/transformed/",
            "50",
            run_date,
            str(is_tc_mode)
        ]
    }
    run_id = f"{tenant_id}-{project_id}-{sbom_id}-{run_date}"
    if part_no:
        run_id += f"-{part_no}"
    #durable_client.start_new(state_machine_arn, client_input=json.dumps(sf_input), instance_id=run_id)
    print(f"Successfully triggered the Durable Function with instance ID: {run_id}")

    # Write the _SUCCESS marker to source container.
    marker_blob_client = blob_service_client.get_blob_client(container=src_container, blob=f"{os.path.dirname(prefix)}/{marker_file_name}")
    marker_blob_client.upload_blob(b"")
    print("Marker file uploaded successfully.")

    return None  # Explicitly returning None to conform to the Azure Functions requirement for blob-triggered functions.