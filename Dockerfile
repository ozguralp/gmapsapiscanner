FROM python:3-alpine AS google_maps_api_scanner
RUN mkdir -p /opt/html
WORKDIR /opt/html
COPY maps_api_scanner_python3.py /opt/maps_api_scanner_python3.py
RUN pip install requests
ENTRYPOINT ["/usr/local/bin/python", "/opt/maps_api_scanner_python3.py", "--api-key"]
