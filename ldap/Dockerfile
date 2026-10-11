# OpenLDAP (slapd) from Debian packages.
# Stage 1 only extracts the Samba LDAP schema (needed for sambaNTPassword, used by PEAP-MSCHAPv2).
FROM debian:bookworm-slim AS schema
RUN apt-get update \
 && cd /tmp && apt-get download samba \
 && dpkg-deb --fsys-tarfile samba_*.deb | tar -x ./usr/share/doc/samba/examples/LDAP/samba.ldif

FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils openssl \
 && rm -rf /var/lib/apt/lists/* /etc/ldap/slapd.d/* /var/lib/ldap/*
COPY --from=schema /tmp/usr/share/doc/samba/examples/LDAP/samba.ldif /etc/ldap/schema/samba.ldif
# Password hashing: Argon2 (slapd's argon2 module, linked with libargon2, so the variant is argon2i).
# 19 MiB memory and 2 passes follow the OWASP minimum for Argon2. Used by slapd and by slappasswd.
ENV ARGON2_MODULE="argon2 m=19456 t=2 p=1"
COPY entrypoint.sh add-user.sh set-disabled.sh /usr/local/bin/
COPY seed/ /seed/
RUN chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/add-user.sh /usr/local/bin/set-disabled.sh
EXPOSE 389
HEALTHCHECK --interval=10s --timeout=5s --retries=12 \
  CMD ldapsearch -x -H ldap://localhost -b "" -s base namingContexts >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
