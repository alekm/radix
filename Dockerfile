FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    freeradius \
    freeradius-python3 \
    python3 \
    python3-psycopg2 \
    && rm -rf /var/lib/apt/lists/*

# Python hook files live alongside the built-in example.py / radiusd.py
COPY hook.py dpsk.py db.py /etc/freeradius/3.0/mods-config/python3/

# FreeRADIUS config overlays
COPY raddb/clients.conf          /etc/freeradius/3.0/clients.conf
COPY raddb/mods-available/python3 /etc/freeradius/3.0/mods-available/python3
COPY raddb/sites-available/radix  /etc/freeradius/3.0/sites-available/radix

RUN ln -sf ../mods-available/python3 /etc/freeradius/3.0/mods-enabled/python3 \
    && ln -sf ../sites-available/radix /etc/freeradius/3.0/sites-enabled/radix \
    && rm -f /etc/freeradius/3.0/sites-enabled/default \
    && rm -f /etc/freeradius/3.0/sites-enabled/inner-tunnel \
    && rm -f /etc/freeradius/3.0/mods-enabled/eap

EXPOSE 1812/udp 1813/udp

CMD ["freeradius", "-f", "-l", "stdout"]
