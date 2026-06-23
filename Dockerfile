# Pinned by digest so the apt snapshot (and thus the psycopg2 / FreeRADIUS
# versions below) is reproducible across rebuilds. Refresh with:
#   docker pull ubuntu:24.04 && docker inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04
FROM ubuntu:24.04@sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54

ENV DEBIAN_FRONTEND=noninteractive

# Snapshot versions (informational): freeradius 3.2.5+dfsg-3~ubuntu24.04.3,
# python3-psycopg2 2.9.9-1build1
RUN apt-get update && apt-get install -y --no-install-recommends \
    freeradius \
    freeradius-python3 \
    python3 \
    python3-psycopg2 \
    && rm -rf /var/lib/apt/lists/*

# Python hook files live alongside the built-in example.py / radiusd.py
COPY hook.py dpsk.py db.py /etc/freeradius/3.0/mods-config/python3/

# FreeRADIUS config overlays
COPY raddb/clients.conf           /etc/freeradius/3.0/clients.conf
COPY raddb/mods-available/python3 /etc/freeradius/3.0/mods-available/python3
COPY raddb/sites-available/radix  /etc/freeradius/3.0/sites-available/radix
COPY raddb/dictionary.tplink      /etc/freeradius/3.0/dictionary.tplink

RUN ln -sf ../mods-available/python3 /etc/freeradius/3.0/mods-enabled/python3 \
    && echo '$INCLUDE /etc/freeradius/3.0/dictionary.tplink' >> /etc/freeradius/3.0/dictionary \
    && ln -sf ../sites-available/radix /etc/freeradius/3.0/sites-enabled/radix \
    && rm -f /etc/freeradius/3.0/sites-enabled/default \
    && rm -f /etc/freeradius/3.0/sites-enabled/inner-tunnel \
    && rm -f /etc/freeradius/3.0/mods-enabled/eap

EXPOSE 1812/udp 1813/udp

CMD ["freeradius", "-f", "-l", "stdout"]
