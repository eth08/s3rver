# test_s3rver.py

import ipaddress
import unittest
import os
import shutil
import threading
import time
import requests
import pytest
import ssl

# Imports for certificate generation
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import tempfile # For creating temporary directory for certs
import subprocess # For OpenSSL fallback

from s3rver import run_server

SERVER_PORT = 8081
BASE_URL = f"http://127.0.0.1:{SERVER_PORT}"

# New ports and URLs for HTTPS
HTTPS_SERVER_PORT = 8082
HTTPS_BASE_URL = f"https://127.0.0.1:{HTTPS_SERVER_PORT}"

UPLOAD_DIR = "upz"
DOWNZ_DIR = "downz"

# Function to generate self-signed certificates for testing
def generate_self_signed_cert(cert_path, key_path):
    try:
        # Generate the private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Generate the CSR (Certificate Signing Request)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Emilia-Romagna"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Bologna"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"RedTeamProject"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        # Add Subject Alternative Name for localhost
        alt_names = [x509.DNSName(u"localhost"), x509.IPAddress(ipaddress.IPv4Address(u"127.0.0.1"))]
        san_extension = x509.SubjectAlternativeName(alt_names)

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10) # Certificate valid for 10 days
        ).add_extension(
            san_extension, critical=False, # Add the SAN extension
        ).sign(key, hashes.SHA256()) 

        # Write the private key to disk
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Write the certificate to disk
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"Generated SSL certificate at {cert_path} and key at {key_path} using cryptography.")

    except Exception as e:
        print(f"Error generating SSL certs with cryptography: {e}. Attempting OpenSSL fallback.")
        # Fallback to OpenSSL CLI if cryptography fails (e.g., due to environment issues)
        try:
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', key_path, '-out', cert_path, '-days', '365',
                            '-subj', '/CN=localhost'], check=True, capture_output=True, text=True)
            print(f"Generated SSL certificate at {cert_path} and key at {key_path} using OpenSSL.")
        except FileNotFoundError:
            raise RuntimeError("OpenSSL command not found. Please install OpenSSL or ensure it's in your PATH.")
        except subprocess.CalledProcessError as sub_e:
            print(f"OpenSSL command failed: {sub_e.stderr}")
            raise RuntimeError(f"Failed to generate SSL certs with OpenSSL: {sub_e}")
        except Exception as fallback_e:
            raise RuntimeError(f"An unexpected error occurred during OpenSSL fallback: {fallback_e}")

def wait_for_server_start(url, timeout=30, interval=1, verify=False):
    """
    Polls the given URL until it returns a successful response (2xx) or timeout is reached.
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            # Use a very short timeout for the connection attempt itself
            response = requests.get(url, timeout=5, verify=verify)
            if 200 <= response.status_code < 300:
                print(f"Server at {url} is up and running (status: {response.status_code}).")
                return True
        except requests.exceptions.ConnectionError:
            print(f"Waiting for server at {url}...")
        except requests.exceptions.Timeout:
            print(f"Connection to {url} timed out, retrying...")
        except Exception as e:
            print(f"An unexpected error occurred while waiting for {url}: {e}")

        time.sleep(interval)
    raise RuntimeError(f"Server at {url} did not start in time after {timeout} seconds.")

@pytest.fixture(scope="session", autouse=True)
def setup_server():
    # Clean and prepare directories
    shutil.rmtree(UPLOAD_DIR, ignore_errors=True)
    shutil.rmtree(DOWNZ_DIR, ignore_errors=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(DOWNZ_DIR, exist_ok=True)

    # Create dummy files for HTTP/HTTPS tests
    with open(os.path.join(DOWNZ_DIR, "file.txt"), "w") as f:
        f.write("Hello Test")

    # Generate a dummy SSL certificate and key for HTTPS tests
    temp_dir = tempfile.mkdtemp()
    certfile = os.path.join(temp_dir, "server.crt")
    keyfile = os.path.join(temp_dir, "server.key")

    try:
        generate_self_signed_cert(certfile, keyfile)
    except RuntimeError as e:
        # If certificate generation fails, propagate the error immediately
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise e

    # Start HTTP server in background
    http_thread = threading.Thread(target=run_server, kwargs={"port": SERVER_PORT}, daemon=True)
    http_thread.start()
    # Wait for HTTP server to be ready
    wait_for_server_start(BASE_URL)

    # Start HTTPS server in background
    https_thread = threading.Thread(target=run_server,
                                    kwargs={"port": HTTPS_SERVER_PORT, "use_https": True,
                                            "certfile": certfile, "keyfile": keyfile},
                                    daemon=True)
    https_thread.start()
    # Wait for HTTPS server to be ready, passing the certfile for verification
    wait_for_server_start(HTTPS_BASE_URL, verify=certfile)

    yield certfile # Yield the certfile path for tests that need it for verification

    # Cleanup after tests
    shutil.rmtree(UPLOAD_DIR, ignore_errors=True)
    shutil.rmtree(DOWNZ_DIR, ignore_errors=True)
    shutil.rmtree(temp_dir, ignore_errors=True) # Clean up temporary cert directory

def test_get_root():
    r = requests.get(BASE_URL + "/")
    assert r.status_code == 200
    assert "Welcome" in r.text

def test_get_status():
    r = requests.get(BASE_URL + "/status")
    assert r.status_code == 200
    # Corrected assertion to check the JSON response
    assert r.json().get('status') == 'ok'

def test_get_file():
    r = requests.get(BASE_URL + "/downz/file.txt")
    assert r.status_code == 200
    assert r.text == "Hello Test"

def test_get_file_not_found():
    r = requests.get(BASE_URL + "/downz/nonexistent.txt")
    assert r.status_code == 404
    assert "404 Not Found" in r.text

def test_get_directory_listing_forbidden():
    r = requests.get(BASE_URL + "/downz/")
    assert r.status_code == 403
    assert "403 Forbidden" in r.text

def test_get_forbidden_traversal():
    r = requests.get(BASE_URL + "/../etc/passwd")
    assert r.status_code == 403

def test_get_forbidden_dot_slash():
    r = requests.get(BASE_URL + "/./downz/file.txt")
    # Expected 200, as /./downz/file.txt normalizes to /downz/file.txt which is valid
    assert r.status_code == 200

def test_get_forbidden():
    r = requests.get(BASE_URL + "/forbidden")
    assert r.status_code == 404 # Should now be 404 as /forbidden is not a defined route

def test_post_json():
    headers = {"Content-Type": "application/json"}
    data = {"key": "value"}
    r = requests.post(BASE_URL + "/submit", json=data, headers=headers)
    assert r.status_code == 200
    response_json = r.json() # Parse the JSON response
    assert response_json.get("message") == "JSON received successfully"
    assert response_json.get("data") == data # Check the actual data object

def test_post_json_bad():
    # Bad JSON format
    bad_data = "{invalid_json"
    headers = {"Content-Type": "application/json"}
    r = requests.post(BASE_URL + "/submit", data=bad_data, headers=headers)
    assert r.status_code == 400

def test_post_form():
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = "name=TestUser&message=Hello+World"
    r = requests.post(BASE_URL + "/submit", data=data, headers=headers)
    assert r.status_code == 200
    assert "Form received successfully" in r.text # Updated to match server's message

def test_post_form_bad():
    bad_data = "%zz"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(BASE_URL + "/submit", data=bad_data, headers=headers)
    assert r.status_code == 200

def test_post_file_upload():
    r = requests.post(BASE_URL + "/upload?filename=test_upload.txt", data=b"somecontent",
                      headers={"Content-Type": "application/octet-stream", "Content-Length": str(len(b"somecontent"))})
    assert r.status_code == 200
    assert "File 'test_upload.txt' uploaded successfully." in r.text
    assert os.path.exists(os.path.join(UPLOAD_DIR, "test_upload.txt"))

def test_post_file_duplicate():
    fname = "dup.txt"
    # First upload
    requests.post(BASE_URL + f"/upload?filename={fname}", data=b"dupdata",
                  headers={"Content-Type": "application/octet-stream", "Content-Length": str(len(b"dupdata"))})
    # Second upload (should create dup(1).txt)
    r = requests.post(BASE_URL + f"/upload?filename={fname}", data=b"dupdata2",
                      headers={"Content-Type": "application/octet-stream", "Content-Length": str(len(b"dupdata2"))})
    assert r.status_code == 200
    # Corrected assertion string for duplicate filename and server message
    assert f"File 'dup(1).txt' uploaded successfully." in r.text
    files = [f for f in os.listdir(UPLOAD_DIR) if f.startswith("dup")]
    assert len(files) == 2
    assert f"{fname}" in files
    assert f"dup(1).txt" in files


def test_post_file_upload_too_large():
    # Assuming MAX_UPLOAD_MB_DEFAULT is 10MB
    large_content = b'A' * (10 * 1024 * 1024 + 1) # 1 byte over 10MB
    r = requests.post(BASE_URL + "/upload?filename=large_file.bin", data=large_content,
                      headers={"Content-Type": "application/octet-stream", "Content-Length": str(len(large_content))})
    assert r.status_code == 413
    assert "413 Payload Too Large" in r.text

def test_put_file_upload():
    fname = "put_file.txt"
    content = b"content for put"
    r = requests.put(BASE_URL + f"/upload?filename={fname}", data=content,
                     headers={"Content-Type": "application/octet-stream", "Content-Length": str(len(content))})
    assert r.status_code == 200
    assert f"File '{fname}' uploaded successfully." in r.text
    assert os.path.exists(os.path.join(UPLOAD_DIR, fname))
    with open(os.path.join(UPLOAD_DIR, fname), 'rb') as f:
        assert f.read() == content


# HTTPS Tests
def test_get_root_https(setup_server):
    cert_file_path = setup_server
    r = requests.get(HTTPS_BASE_URL + "/", verify=cert_file_path)
    assert r.status_code == 200
    assert "Welcome" in r.text

def test_get_file_https(setup_server):
    cert_file_path = setup_server
    r = requests.get(HTTPS_BASE_URL + "/downz/file.txt", verify=cert_file_path)
    assert r.status_code == 200
    assert r.text == "Hello Test"

def test_get_forbidden_https(setup_server):
    cert_file_path = setup_server
    r = requests.get(HTTPS_BASE_URL + "/../etc/passwd", verify=cert_file_path)
    assert r.status_code == 403

def test_post_json_https(setup_server):
    cert_file_path = setup_server
    headers = {"Content-Type": "application/json"}
    data = {"secure_key": "secure_value"}
    r = requests.post(HTTPS_BASE_URL + "/submit", json=data, headers=headers, verify=cert_file_path)
    assert r.status_code == 200
    response_json = r.json() # Parse the JSON response
    assert response_json.get("message") == "JSON received successfully"
    assert response_json.get("data") == data # Check the actual data object


def test_post_file_upload_https(setup_server):
    cert_file_path = setup_server
    file_content = b"this is a secure test file content."
    r = requests.post(HTTPS_BASE_URL + "/upload?filename=secure_upload.txt", data=file_content,
                      headers={"Content-Type": "application/octet-stream", "Content-Length": str(len(file_content))}, verify=cert_file_path)
    assert r.status_code == 200
    assert "File 'secure_upload.txt' uploaded successfully." in r.text
    assert os.path.exists(os.path.join(UPLOAD_DIR, "secure_upload.txt"))