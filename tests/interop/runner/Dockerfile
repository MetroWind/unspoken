FROM python:3.12-alpine

RUN apk add --no-cache curl jq sqlite

WORKDIR /runner

COPY interop.py /runner/interop.py

ENTRYPOINT ["python", "/runner/interop.py"]
