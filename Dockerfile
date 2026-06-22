FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    freeradius \
    freeradius-python3 \
    python3 \
    python3-psycopg2 \
    && rm -rf /var/lib/apt/lists/*

# Python hook
COPY hook.py dpsk.py db.py /etc/raddb/python/

# FreeRADIUS config overlays (on top of the default install)
COPY raddb/clients.conf /etc/raddb/clients.conf
COPY raddb/mods-available/python3 /etc/raddb/mods-available/python3
COPY raddb/sites-available/radix /etc/raddb/sites-available/radix

RUN ln -sf ../mods-available/python3 /etc/raddb/mods-enabled/python3 \
    && ln -sf ../sites-available/radix /etc/raddb/sites-enabled/radix \
    && rm -f /etc/raddb/sites-enabled/default \
    && rm -f /etc/raddb/sites-enabled/inner-tunnel

EXPOSE 1812/udp 1813/udp

CMD ["freeradius", "-f", "-l", "stdout"]
