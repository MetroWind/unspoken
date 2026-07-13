FROM python:3.12-alpine

RUN apk add --no-cache openssl

WORKDIR /peer

COPY lifecycle_peer.py /peer/lifecycle_peer.py

ENTRYPOINT ["python", "/peer/lifecycle_peer.py"]
