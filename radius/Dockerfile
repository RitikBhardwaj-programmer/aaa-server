FROM freeradius/freeradius-server:3.2.10

# Our configuration replaces only these stock files; everything else stays as shipped.
COPY raddb/clients.conf                  /etc/freeradius/clients.conf
COPY raddb/mods-available/ldap           /etc/freeradius/mods-available/ldap
COPY raddb/mods-available/eap            /etc/freeradius/mods-available/eap
COPY raddb/mods-available/inner-eap      /etc/freeradius/mods-available/inner-eap
COPY raddb/mods-available/sql            /etc/freeradius/mods-available/sql
COPY raddb/mods-available/sql_spool      /etc/freeradius/mods-available/sql_spool
COPY raddb/mods-config/sql/main/postgresql/queries.conf /etc/freeradius/mods-config/sql/main/postgresql/queries.conf
COPY raddb/sites-available/default       /etc/freeradius/sites-available/default
COPY raddb/sites-available/inner-tunnel  /etc/freeradius/sites-available/inner-tunnel
COPY raddb/sites-available/buffered-sql  /etc/freeradius/sites-available/buffered-sql
COPY raddb/sites-available/check-eap-tls /etc/freeradius/sites-available/check-eap-tls
COPY raddb/policy.d/campus               /etc/freeradius/policy.d/campus
COPY radius-start.sh                     /usr/local/bin/radius-start.sh

RUN ln -sf ../mods-available/ldap      /etc/freeradius/mods-enabled/ldap \
 && ln -sf ../mods-available/inner-eap /etc/freeradius/mods-enabled/inner-eap \
 && ln -sf ../mods-available/sql       /etc/freeradius/mods-enabled/sql \
 && ln -sf ../mods-available/sql_spool /etc/freeradius/mods-enabled/sql_spool \
 && ln -sf ../sites-available/buffered-sql /etc/freeradius/sites-enabled/buffered-sql \
 && ln -sf ../sites-available/check-eap-tls /etc/freeradius/sites-enabled/check-eap-tls \
 # Log every accept/reject (with the reason, never the password) to the server log
 && sed -i 's/^\(\s*auth\) = no/\1 = yes/' /etc/freeradius/radiusd.conf \
 && chmod 755 /usr/local/bin/radius-start.sh

ENTRYPOINT ["/usr/local/bin/radius-start.sh"]
CMD ["-l", "stdout"]
