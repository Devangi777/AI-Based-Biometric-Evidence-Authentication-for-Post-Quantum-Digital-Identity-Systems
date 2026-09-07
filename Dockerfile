# Server-side image: crypto/ + detection/ + binding/ + server/ + evaluation/
#
# Built on Debian slim + the full liboqs build toolchain (cmake, ninja, gcc)
# so that `pip install liboqs-python` can compile the native liboqs C library
# on first import, per Section 11 of PQ-Biometric-Auth-Spec.md. This is the
# split-architecture fallback used because that build reliably fails on
# native Windows without Visual Studio Build Tools.
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# liboqs build toolchain + OpenCV/mediapipe runtime shared libs
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        ninja-build \
        git \
        libssl-dev \
        python3-dev \
        libgl1 \
        libglib2.0-0 \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Pre-warm the liboqs native build at image-build time (not first request) by
# importing oqs once. Keeps container startup fast and fails the build early
# and loudly if the toolchain is broken, instead of failing a demo mid-request.
RUN python -c "import oqs; k = oqs.KeyEncapsulation('ML-KEM-768'); k.generate_keypair(); print('liboqs OK:', oqs.oqs_python_version())"

COPY crypto/ ./crypto/
COPY detection/ ./detection/
COPY binding/ ./binding/
COPY server/ ./server/
COPY evaluation/ ./evaluation/

EXPOSE 8000

CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
