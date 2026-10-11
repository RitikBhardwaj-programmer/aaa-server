#!/bin/sh
# Runs once, when the database volume is empty (docker-entrypoint-initdb.d).
# Creates the non-superuser role that FreeRADIUS, the maintenance job and the tests use.
# psql reads the password from its environment (\getenv), never from a command line.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOF'
\getenv pw POSTGRES_RADIUS_PASSWORD
CREATE ROLE radius LOGIN PASSWORD :'pw';
GRANT ALL ON SCHEMA public TO radius;
EOF
