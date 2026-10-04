# Test client: eapol_test (a real 802.1X supplicant without Wi-Fi), radtest/radclient, sqlite3.
FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends eapoltest freeradius-utils sqlite3 \
 && rm -rf /var/lib/apt/lists/*
COPY run-tests.sh /usr/local/bin/run-tests.sh
RUN chmod 755 /usr/local/bin/run-tests.sh
ENTRYPOINT ["/usr/local/bin/run-tests.sh"]
