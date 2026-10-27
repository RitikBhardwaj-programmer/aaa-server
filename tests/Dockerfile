# Test client: eapol_test (a real 802.1X supplicant without Wi-Fi), radtest/radclient, psql, and
# openssl (EAP-TLS client certificates of the Device CA).
FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends eapoltest freeradius-utils postgresql-client openssl \
 && rm -rf /var/lib/apt/lists/*
COPY run-tests.sh disconnect-user.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/run-tests.sh /usr/local/bin/disconnect-user.sh
ENTRYPOINT ["/usr/local/bin/run-tests.sh"]
