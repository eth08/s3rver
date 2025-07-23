# s3rver.py

import argparse
import logging
import ssl
import os
import re
import json
import uuid
from urllib.parse import urlparse, parse_qs, unquote_plus
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import mimetypes

# --- Script Version ---
SCRIPT_VERSION = "0.4.8"

MAX_UPLOAD_MB_DEFAULT = 10

# --- Logging ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('http_s3rver.log'),
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    MIME_TYPES = {
        '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
        '.png': 'image/png', '.jpg': 'image/jpeg', '.gif': 'image/gif',
        '.ico': 'image/x-icon', '.json': 'application/json', '.txt': 'text/plain',
        '.zip': 'application/zip', '.tar.gz': 'application/gzip', '.exe': 'application/x-ms-dos-executable',
        '.elf': 'application/x-executable', '.bin': 'application/octet-stream', '.pdf': 'application/pdf'
    }

    def _set_response(self, code=200, content_type='text/html'):
        self.send_response(code)
        self.send_header('Content-type', content_type)
        self.end_headers()

    def _generate_unique_filename(self, folder, filename):
        name, ext = os.path.splitext(filename)
        counter = 1
        candidate = filename
        while os.path.exists(os.path.join(folder, candidate)):
            candidate = f"{name}({counter}){ext}"
            counter += 1
        return candidate

    def _get_safe_filepath(self, base_directory, requested_filename_or_path):
        """
        Safely resolves a requested path to a filesystem path within a base directory.
        Prevents directory traversal attacks.
        `requested_filename_or_path` is expected to be already URL-decoded and
        normalized relative to the conceptual base_directory, but could still contain '..' components.
        """
        canonical_base_dir = os.path.realpath(base_directory)
        
        # Normalize the requested path to resolve any '..' or '.'
        normalized_requested_path = os.path.normpath(requested_filename_or_path)

        # Construct the full path within the base directory
        full_path = os.path.join(canonical_base_dir, normalized_requested_path)
        
        # Canonicalize to resolve all symlinks and `.` `..` to their true filesystem paths
        canonical_full_path = os.path.realpath(full_path)

        # CRITICAL CHECK: Ensure the canonicalized path is *still* inside the canonical base directory
        # Use `startswith` with `os.sep` to prevent accessing `base_directory` itself as a file
        # if it's a directory (e.g., requesting '/downz' should give 403, not serve it as a file).
        # We also explicitly allow the canonical_base_dir itself if it's a file (e.g., index.html inside it).
        if not canonical_full_path.startswith(canonical_base_dir + os.sep) and \
           canonical_full_path != canonical_base_dir:
            raise PermissionError(f"Directory traversal attempt detected: {requested_filename_or_path}")

        # Prevent directory listing for any subdirectories within the base directory
        if os.path.isdir(canonical_full_path):
            raise IsADirectoryError("Directory listing is not allowed.")

        return canonical_full_path

    def do_GET(self):
        try:
            parsed_path = urlparse(self.path)
            path = parsed_path.path
            query_params = parse_qs(parsed_path.query)

            # Define explicitly forbidden system paths
            forbidden_system_paths = ['/etc/passwd', '/etc/shadow', '/proc/self/cmdline', '/boot/grub/grub.cfg']
            if path in forbidden_system_paths:
                logger.warning(f"Explicitly forbidden system path requested: {self.path}")
                self._set_response(403)
                self.wfile.write(b"403 Forbidden: Access to system files is denied.")
                return

            # Handle specific API endpoints first
            if path == '/':
                self._set_response()
                self.wfile.write(b"<h1>Welcome, s3rver is up and running!</h1>")
                return
            elif path == '/status':
                self._set_response(200, 'application/json')
                payload = {
                    'status': 'ok', 
                    'server_time': self.date_time_string(),
                    'server_name': 'Simple Secure HTTP/HTTPS Server (a.k.a. s3rver)', 
                    'server_version': f"{SCRIPT_VERSION}"
                }
                self.wfile.write(json.dumps(payload).encode('utf-8'))
                return
            elif path.startswith('/downz/'):
                # For /downz/ requests, use the safe path resolver strictly within 'downz'
                requested_subpath = path[len('/downz/'):] # e.g., 'file.txt' or 'subdir/another.txt'
                try:
                    filepath_to_serve = self._get_safe_filepath('downz', requested_subpath)
                    
                    if os.path.exists(filepath_to_serve) and os.path.isfile(filepath_to_serve):
                        ext = os.path.splitext(filepath_to_serve)[1].lower()
                        mime_type = self.MIME_TYPES.get(ext, 'application/octet-stream')
                        self._set_response(200, mime_type)
                        with open(filepath_to_serve, 'rb') as file:
                            self.wfile.write(file.read())
                        logger.info(f"Served file from /downz: {filepath_to_serve}")
                    else:
                        self._set_response(404)
                        self.wfile.write(b"404 Not Found")
                        logger.warning(f"File not found in /downz/: {self.path}")
                except (PermissionError, IsADirectoryError) as e:
                    logger.warning(f"Blocked request for {self.path}: {e}")
                    self._set_response(403)
                    self.wfile.write(b"403 Forbidden: " + str(e).encode('utf-8'))
                return
            
            # For any other path not explicitly routed (including other absolute paths like /random_file.txt)
            self._set_response(404)
            self.wfile.write(b"404 Not Found: Resource not found.")
            logger.warning(f"Unhandled GET request: {self.path}")

        except Exception as e:
            logger.error(f"Error during GET request handling for {self.path}: {e}", exc_info=True)
            self._set_response(500)
            self.wfile.write(f"500 Internal Server Error: {e}".encode('utf-8'))


    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            max_bytes = getattr(self.server, 'max_upload_bytes', MAX_UPLOAD_MB_DEFAULT * 1024 * 1024)
            if length > max_bytes:
                self._set_response(413)
                self.wfile.write(b"413 Payload Too Large")
                return

            raw = self.rfile.read(length)
            ctype = self.headers.get('Content-Type', '').lower()

            if 'application/json' in ctype:
                self._handle_json(raw)
            elif 'application/x-www-form-urlencoded' in ctype:
                self._handle_form(raw)
            else: # Default to file upload if content-type is not JSON or form
                self._handle_file(raw)
        except Exception as e:
            logger.exception("POST error: %s", e)
            self._set_response(500)
            self.wfile.write(b"500 Internal Server Error")

    def _handle_json(self, raw):
        try:
            data = json.loads(raw.decode('utf-8'))
            logger.info("JSON received: %s", json.dumps(data, indent=2))
            self._set_response(200, 'application/json') # Set content type to JSON
            response_message = {"status": "success", "message": "JSON received successfully", "data": data}
            self.wfile.write(json.dumps(response_message, indent=2).encode('utf-8'))
        except json.JSONDecodeError:
            self._set_response(400)
            self.wfile.write(b"400 Bad Request: Invalid JSON")

    def _handle_form(self, raw):
        try:
            decoded = raw.decode('utf-8')
            data = parse_qs(decoded)
            logger.info("Form data: %s", data)
            self._set_response()
            self.wfile.write(b"Form received successfully")
        except UnicodeDecodeError: # Catch actual decoding errors if any invalid bytes
            self._set_response(400)
            self.wfile.write(b"400 Bad Request: Invalid form encoding")
        except Exception: # Catch other potential errors
            self._set_response(400)
            self.wfile.write(b"400 Bad Request: Invalid form data")

    def _handle_file(self, raw):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        # Attempt to get filename from query param or generate unique
        original_filename = query.get('filename', [None])[0]

        if not original_filename:
            # Fallback to Content-Disposition header if filename not in query
            content_disposition = self.headers.get('Content-Disposition')
            if content_disposition:
                fname_match = re.search(r'filename\*?=(?:UTF-8\'\')?\"?([^\"]+)\"?', content_disposition)
                if fname_match:
                    original_filename = unquote_plus(fname_match.group(1)) # Handle URL-encoded filenames

        if not original_filename:
            # Generate a unique filename if no filename is provided in query or Content-Disposition
            content_type = self.headers.get('Content-Type', 'application/octet-stream')
            ext = mimetypes.guess_extension(content_type)
            if not ext:
                ext = '.bin' # Default binary extension
            original_filename = f"uploaded_data_{uuid.uuid4().hex}{ext}"

        upload_dir = getattr(self.server, 'upz_directory', 'upz')
        os.makedirs(upload_dir, exist_ok=True)
        
        # Prevent path traversal in filename itself (e.g., filename='../malicious.txt')
        safe_name = os.path.basename(original_filename) 

        # Generate unique filename for duplicates
        final_save_name = self._generate_unique_filename(upload_dir, safe_name)
        save_path = os.path.join(upload_dir, final_save_name)

        with open(save_path, 'wb') as f:
            f.write(raw)
        logger.info("Saved upload: %s (%d bytes)", save_path, len(raw))
        self._set_response()
        self.wfile.write(f"File '{final_save_name}' uploaded successfully.".encode('utf-8'))

    def do_PUT(self):
        # Re-use POST handling for PUT requests
        self.do_POST()

def run_server(port=8080, use_https=False, certfile=None, keyfile=None, max_upload_mb=10):
    server_address = ('', port)
    httpd = ThreadedHTTPServer(server_address, SimpleHTTPRequestHandler)
    httpd.upz_directory = 'upz'
    httpd.max_upload_bytes = max_upload_mb * 1024 * 1024

    if use_https:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            logger.info("Starting HTTPS on port %d", port)
        except ssl.SSLError as e:
            logger.error(f"SSL Error during HTTPS server startup: {e}", exc_info=True)
            raise RuntimeError(f"Failed to start HTTPS server due to SSL error: {e}") from e
        except FileNotFoundError as e:
            logger.error(f"Certificate or key file not found: {e}", exc_info=True)
            raise RuntimeError(f"Failed to start HTTPS server: Certificate or key file not found: {e}") from e
        except Exception as e:
            logger.error(f"General error during HTTPS server startup: {e}", exc_info=True)
            raise RuntimeError(f"Failed to start HTTPS server due to unexpected error: {e}") from e
    else:
        logger.info("Starting HTTP on port %d", port)
    
    logger.info(f"Simple Secure HTTP/HTTPS Server (Version: {SCRIPT_VERSION})") # Log the script version
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopping gracefully...")
    except Exception as e:
        logger.error(f"Server encountered an error during startup or operation: {e}", exc_info=True)
    finally:
        httpd.server_close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=f"Simple Secure HTTP/HTTPS Server (Version: {SCRIPT_VERSION})")
    parser.add_argument('-p', '--port', type=int, default=8080)
    parser.add_argument('-s', '--secure', action='store_true',
                        help='Enable HTTPS (requires --certfile and --keyfile)')
    parser.add_argument('-c', '--certfile', type=str,
                        help='Path to SSL certificate file (e.g., server.crt)')
    parser.add_argument('-k', '--keyfile', type=str,
                        help='Path to SSL private key file (e.g., server.key)')
    parser.add_argument('--max-upload-mb', type=int, default=MAX_UPLOAD_MB_DEFAULT,
                        help='Max upload file size (MB)')
    
    args = parser.parse_args()

    # Basic validation for HTTPS
    if args.secure and (not args.certfile or not args.keyfile):
        parser.error("--secure requires --certfile and --keyfile arguments.")

    # Create 'downz' directory and some dummy files for testing downloads
    if not os.path.exists('downz'):
        os.makedirs('downz')
        logger.info("Created 'downz' directory for file downloads.")
    
    # Create an 'upz' directory for received files
    if not os.path.exists('upz'):
        os.makedirs('upz')
        logger.info("Created 'upz' directory for file uploads.")


    run_server(
        port=args.port,
        use_https=args.secure,
        certfile=args.certfile,
        keyfile=args.keyfile,
        max_upload_mb=args.max_upload_mb
    )