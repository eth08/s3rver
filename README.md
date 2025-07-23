# Simple Secure HTTP/HTTPS Server

![Python CI/CD](https://github.com/eth08/s3rver/actions/workflows/main.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Version](https://img.shields.io/badge/version-0.4.8-orange)

A secure, lightweight HTTP/HTTPS Python server with **safe file serving**, **upload support**, and **basic REST-like endpoints**.

## Features

- **Secure file serving** from `/downz/` directory:
  - Prevents directory traversal & system file access.
  - Blocks dangerous paths (`/etc/passwd`, `/proc/self/cmdline`, etc.).
- **File uploads** with:
  - Windows-style duplicate naming (`file(1).txt`, `file(2).txt`).
  - Safe filename sanitization & max size limit (`--max-upload-mb`, default: 10 MB).
- **Basic endpoints**:
  - `GET /` → Welcome message.
  - `GET /status` → JSON server status & version.
  - `GET /downz/<file>` → Secure file download.
  - `POST /upload` → File uploads (binary, form, or JSON).
- **HTTPS Support**:
  - TLS certificates (`--certfile` & `--keyfile`).
- **Verbose logging** to `http_s3rver.log`.
- **Threaded server** for concurrent requests.

The server automatically creates `downz` and `upz` directories if they don't exist.



## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/eth08/s3rver.git
    cd s3rver
    ```

2.  **Install dependencies:**
    It's highly recommended to use a virtual environment.
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```



## Usage

### Start HTTP server (default)
```bash
python s3rver.py -p 8080
```

### Start HTTPS server
```bash
python s3rver.py -p 8443 -s -c server.crt -k server.key
```

### Optional parameters
```bash
--max-upload-mb 50      # Set max upload size (default: 10 MB)
```

### Command line help
```bash
python s3rver.py -h
```

### Download a file from the server (folder '/downz'). Example with 'curl'
```bash
curl http://localhost:8080/downz/my_file.txt -o my_file.txt  
```

### Upload a file to the server (folder '/upz'). Example with 'curl'
```bash
curl -X POST -H "Content-Type: application/zip" --data-binary @my_file.zip http://localhost:8080/upload?filename=my_file.zip
```



## Endpoints Overview

| Method | Endpoint                 | Description                                      |
|--------|--------------------------|--------------------------------------------------|
| GET    | `/`                      | Welcome message                                  |
| GET    | `/status`                | JSON server status                               |
| GET    | `/downz/<file>`          | Securely download a file                         |
| POST   | `/upload?filename=name`  | Upload a file (binary/form/json)                 |
| PUT    | `/upload?filename=name`  | Same as POST (PUT supported)                     |



## Security

- **Directory traversal protection** using canonical path checks.
- **Explicitly blocked system files** (e.g., `/etc/passwd`).
- **Uploads**: Filenames sanitized (`os.path.basename`) & duplicates renamed (`file(1).txt`).
- **Max upload size** configurable (HTTP 413 for too large files).



## Development & Testing

### Running Tests
To run the unit tests:

```bash
pip install -r requirements.txt
pytest test_s3rver.py
```
