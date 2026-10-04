FROM freeradius/freeradius-server:3.2.10

# Our configuration replaces only these stock files; everything else stays as shipped.
COPY raddb/clients.conf                  /etc/freeradius/clients.conf
COPY raddb/mods-available/ldap           /etc/freeradius/mods-available/ldap
COPY raddb/mods-available/eap            /etc/freeradius/mods-available/eap
COPY raddb/mods-available/sql            /etc/freeradius/mods-available/sql
COPY raddb/sites-available/default       /etc/freeradius/sites-available/default
COPY raddb/sites-available/inner-tunnel  /etc/freeradius/sites-available/inner-tunnel
COPY raddb/policy.d/campus               /etc/freeradius/policy.d/campus
COPY radius-start.sh                     /usr/local/bin/radius-start.sh

RUN ln -sf ../mods-available/ldap /etc/freeradius/mods-enabled/ldap \
 && ln -sf ../mods-available/sql  /etc/freeradius/mods-enabled/sql \
 # Log every accept/reject (with the reason, never the password) to the server log
 && sed -i 's/^\(\s*auth\) = no/\1 = yes/' /etc/freeradius/radiusd.conf \
 # Store the Class attribute (= LDAP group, set in policy.d/campus) in radacct and radpostauth
 && sed -i -e "s/^\(\s*column_name\s*=\).*/\1 \", class\"/" \
           -e "s/^\(\s*packet_xlat\s*=\).*/\1 \", '%{string:\&Class}'\"/" \
           -e "s/^\(\s*reply_xlat\s*=\).*/\1 \", '%{string:\&reply:Class}'\"/" \
        /etc/freeradius/mods-config/sql/main/sqlite/queries.conf \
 && chmod 755 /usr/local/bin/radius-start.sh

ENTRYPOINT ["/usr/local/bin/radius-start.sh"]
CMD ["-l", "stdout"]
