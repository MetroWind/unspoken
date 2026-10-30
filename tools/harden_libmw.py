#!/usr/bin/env python3
"""Apply the transport options missing from libmw's session interface.

Filtered sessions must connect directly to the filtered destination, rather
than an environment-selected proxy. Decode compression before streaming so
application byte bounds apply to decoded content. Keep this patch idempotent
for existing FetchContent checkouts and remove it when libmw provides these
settings itself.
"""
import pathlib
import sys

source = pathlib.Path(sys.argv[1]) / "url/src/http_client.cpp"
text = source.read_text()
marker = "    curl_easy_reset(handle);"
addition = '''
    // Application transport hardening for resolved-address filtered requests.
    if(addr_filter)
    {
        curl_easy_setopt(handle, CURLOPT_PROXY, "");
        curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "");
    }
'''
if addition not in text:
    if text.count(marker) != 1:
        raise RuntimeError("libmw request setup changed; review transport patch")
    source.write_text(text.replace(marker, marker + addition))
