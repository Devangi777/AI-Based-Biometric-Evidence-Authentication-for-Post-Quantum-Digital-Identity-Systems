# Windows Setup Guide

This project needs `liboqs` (the C library behind `oqs-python`), which
usually has **no prebuilt wheel** for a given Windows/Python combination —
`pip install liboqs-python` installs a thin Python wrapper that then tries to
**compile liboqs from source on first `import oqs`**, requiring Visual Studio
Build Tools, CMake, and Ninja. If those aren't present, the import fails.

This was actually verified on the machine this project was built on:

```
$ pip install liboqs-python          # succeeds - just installs the wrapper
$ python -c "import oqs; oqs.KeyEncapsulation('ML-KEM-768').generate_keypair()"
liboqs not found, installing it in C:\Users\<you>\_oqs
...
'cmake' is not recognized as an internal or external command,
operable program or batch file.
Error installing liboqs.
RuntimeError: No oqs shared libraries found
```

Follow the steps below **in order** and stop as soon as one works.

## Step 0 — Prerequisites (all paths)

- Python 3.11 (project target; see README.md "Assumptions" if you only have
  3.10 available for the native/client side)
- Git
- A webcam, for the live-capture demo mode

## Step 1 — Try the native pip wheel first

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install liboqs-python
python -c "import oqs; k = oqs.KeyEncapsulation('ML-KEM-768'); k.generate_keypair(); print('liboqs OK')"
```

- **If this prints `liboqs OK`:** your machine already has a working
  cmake/ninja/C-compiler toolchain (or a cached liboqs build). You can install
  `requirements.txt` natively and skip straight to running
  `uvicorn server.main:app` without Docker. Still install
  `requirements-client.txt` for the Streamlit demo as in Step 3.
- **If it fails** (as it did here, with `'cmake' is not recognized...`):
  continue to Step 2. Do **not** try to work around this by swapping in a
  different crypto library — that defeats the point of using the
  NIST-standardized, audited `liboqs` implementation. Use the split
  architecture below instead.

## Step 2 — Split architecture (recommended fallback)

Run the crypto + AI server in **Docker Desktop with the WSL2 backend** (where
liboqs builds cleanly on Linux), and run the **Streamlit demo natively on
Windows** (the browser streams the camera to it over WebRTC). They talk over
`localhost:8000`.

### 2a. Enable WSL2

```powershell
wsl --install
wsl --set-default-version 2
```
Reboot if prompted. Verify with `wsl --status` — it should report
`Default Version: 2`.

### 2b. Install Docker Desktop

1. Download and install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/).
2. In Docker Desktop → Settings → General, ensure **"Use the WSL 2 based
   engine"** is checked.
3. In Settings → Resources → WSL Integration, enable integration with your
   default WSL distro.
4. Restart Docker Desktop, then verify from PowerShell:
   ```powershell
   docker --version
   docker compose version
   ```

### 2c. Build and run the server

```powershell
copy .env.example .env
docker compose up --build
```

Watch the build logs for the `liboqs OK: <version>` line printed by the
Dockerfile's warm-up step (`RUN python -c "import oqs; ..."`) — that confirms
liboqs compiled successfully inside the container. First build takes several
minutes (compiling liboqs + installing PyTorch); subsequent builds are cached.

### 2d. Verify the split is talking correctly

With the server container running, from a **separate** PowerShell window (or
inside WSL):

```powershell
curl http://localhost:8000/health
```

Expected response:

```json
{"status": "ok", "kem_alg": "ML-KEM-768", "sig_alg": "ML-DSA-65", "liboqs_ready": true}
```

If you have [HTTPie](https://httpie.io/) instead:

```powershell
http GET http://localhost:8000/health
```

If this fails: check `docker compose logs server` for the liboqs build error,
confirm Docker Desktop's WSL2 integration is enabled (2b.3), and confirm
nothing else is bound to port 8000 (`netstat -ano | findstr :8000`).

## Step 3 — Native Windows venv for the Streamlit demo client

The demo client does **not** need `liboqs`, so it installs cleanly on native
Windows Python with no special toolchain. Without liboqs it sends evidence to
the plaintext `/verify` endpoint (the sidebar says "Client channel:
plaintext"); with liboqs available (macOS/Linux, or inside WSL2) it seals the
payload with ML-KEM-768 + AES-256-GCM via `/verify-sealed`:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-client.txt
streamlit run client_demo/streamlit_app.py
```

The app reads `API_BASE_URL` from `.env` (default `http://localhost:8000`) to
reach the Dockerized server. Confirm the sidebar shows a green "Server
reachable" indicator before starting the demo — see GUIDE.md in the repo root.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `cmake is not recognized` during native `import oqs` | No native build toolchain | Use Step 2 (Docker) instead of fighting the native build |
| `docker: command not found` in PowerShell | Docker Desktop not installed / not on PATH | Install Docker Desktop (2b), reopen PowerShell |
| `docker compose up` hangs at liboqs `cmake` step | WSL2 backend not actually engaged | Docker Desktop → Settings → General → enable "Use the WSL 2 based engine"; restart Docker Desktop |
| Streamlit can't reach the server (`ConnectionError`) | Server container not running, or wrong `API_BASE_URL` | `docker compose ps`; confirm `curl http://localhost:8000/health` works first |
| Camera prompt never appears in the Live Capture tab | Browser blocked camera access, or the page isn't on `localhost` | Allow camera access for `localhost:8501` in the browser's site settings; browsers only expose cameras on `localhost`/HTTPS |
| `ModuleNotFoundError: cv2` in the native venv | Installed `requirements.txt` (server deps) instead of `requirements-client.txt` | `pip install -r requirements-client.txt` in the native venv |

## Running tests

```powershell
# Inside the Docker container (crypto/detection/binding tests):
docker compose exec server pytest tests/ -v

# Or natively, if Step 1 succeeded on your machine:
.venv\Scripts\activate
pip install -r requirements.txt
pytest tests/ -v
```
