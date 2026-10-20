# macOS Setup Guide

This project needs `liboqs` (the C library behind `oqs-python`). On macOS, this
is generally easier than Windows since macOS has a proper Unix-like environment
with standard build tools available through Homebrew and Xcode Command Line Tools.

Follow the steps below **in order**.

## Step 0 — Prerequisites

- Python 3.11
- Git
- Homebrew (recommended for dependency management)
- A webcam, for the live-capture demo mode

## Step 1 — Install system dependencies

### 1a. Install Xcode Command Line Tools

```bash
xcode-select --install
```

Accept the license agreement when prompted. This provides the C compiler and
other build tools needed for compiling liboqs.

### 1b. Install Homebrew (if not already installed)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Follow the post-installation instructions to add Homebrew to your PATH.

### 1c. Install CMake and other build dependencies

```bash
brew install cmake ninja openssl
```

## Step 2 — Choose your setup approach

### Option A: Native Python setup (recommended for macOS)

On macOS, liboqs typically compiles cleanly with the above dependencies, so
you can run everything natively without Docker.

```bash
# Create and activate virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install liboqs-python (this will compile liboqs from source)
pip install liboqs-python

# Verify liboqs works
python -c "import oqs; k = oqs.KeyEncapsulation('ML-KEM-768'); k.generate_keypair(); print('liboqs OK')"

# If the above prints 'liboqs OK', continue with full installation
pip install -r requirements.txt
pip install -r requirements-client.txt

# Run the server
uvicorn server.main:app --host 0.0.0.0 --port 8000
```

### Option B: Docker setup (alternative)

If you prefer containerization or encounter issues with the native build:

```bash
# Install Docker Desktop for Mac from https://www.docker.com/products/docker-desktop/
# After installation, start Docker Desktop

# Build and run with Docker Compose
cp .env.example .env
docker compose up --build
```

## Step 3 — Verify the setup

### For native setup:

With the server running, open a new terminal:

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status": "ok", "kem_alg": "ML-KEM-768", "sig_alg": "ML-DSA-65", "liboqs_ready": true}
```

### For Docker setup:

The verification is the same - Docker Desktop forwards port 8000 to your Mac.

## Step 4 — Run the Streamlit demo client

```bash
source .venv/bin/activate
python scripts/make_demo_assets.py          # once: builds demo_assets/attacks/ (see GUIDE.md)
streamlit run client_demo/streamlit_app.py
```

The app reads `API_BASE_URL` from `.env` (default `http://localhost:8000`).
Because liboqs is installed in the same venv, the sidebar should show both
**Server online** and **Client channel: sealed** (ML-KEM-768 + AES-256-GCM).

## Step 5 — Check the demo end to end

```bash
python scripts/demo_check.py
```

This runs every demo scenario through the real client code and prints the
decision and the check/detector that made it; it should end with
`12/12 scenarios behaved as expected`. Then follow `GUIDE.md`.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `xcode-select: error: tool 'xcodebuild' requires Xcode` | Xcode Command Line Tools not installed | Run `xcode-select --install` and accept the license |
| `cmake: command not found` | CMake not installed or not on PATH | Run `brew install cmake` and restart your terminal |
| `import oqs` fails with compiler errors | Missing build dependencies | Ensure Xcode Command Line Tools and CMake are installed |
| `liboqs OK` doesn't print | liboqs compilation failed | Check the error output; usually missing OpenSSL or build tools |
| `uvicorn: command not found` | Virtual environment not activated | Run `source .venv/bin/activate` |
| Streamlit can't reach the server | Server not running or wrong port | Ensure server is running on port 8000; check `.env` for `API_BASE_URL` |
| Webcam not detected | Browser permissions | Allow camera access for `localhost:8501` in the browser, and in System Settings → Privacy & Security → Camera for the browser |
| `Address already in use` on port 8000 | The Docker container (`docker compose up`) is already serving port 8000 | Use one server: `docker compose down`, or keep Docker and skip the native `uvicorn` |
| `ModuleNotFoundError: cv2` | Wrong requirements file installed | Ensure you ran `pip install -r requirements-client.txt` |

## Running tests

```bash
# Activate virtual environment
source .venv/bin/activate

# Run all tests
pytest tests/ -v

# Run specific test modules
pytest tests/test_crypto.py tests/test_channel.py -v   # ML-KEM / ML-DSA / AES-GCM channel
pytest tests/test_detection.py tests/test_fusion.py -v # detectors and fusion
pytest tests/test_server.py -v                         # API, binding and sealed channel
```

## Quick start summary (one-liner for experienced users)

```bash
# Install dependencies
brew install cmake ninja openssl
python3.11 -m venv .venv && source .venv/bin/activate
pip install liboqs-python && pip install -r requirements.txt && pip install -r requirements-client.txt

# Run server (in one terminal)
uvicorn server.main:app --host 0.0.0.0 --port 8000

# Run demo (in another terminal)
source .venv/bin/activate
streamlit run client_demo/streamlit_app.py
```

## Notes specific to macOS

- **Python version**: Use `python3.11` explicitly if you have multiple Python versions
- **SSL certificates**: macOS may need additional SSL certificate configuration for some packages; Homebrew's OpenSSL usually handles this
- **Camera permissions**: macOS requires explicit camera permissions for browser-based webcam access
- **Performance**: The native setup typically performs better than Docker on macOS since there's no virtualization overhead
- **Rosetta**: If you're on an Apple Silicon Mac (M1/M2/M3), everything should work natively; liboqs compiles fine on ARM64