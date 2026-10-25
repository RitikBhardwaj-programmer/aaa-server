#!/bin/sh
# Sets the password of the database role "portal" from POSTGRES_PORTAL_PASSWORD.
# Run by initdb/03-portal-password.sh on first start, and by hand on an existing database:
#   docker compose exec -T postgres sh /migrations/002-portal-password.sh
# psql reads the password from its own environment (\getenv), so it never appears in a
# command line (visible in /proc) or in a SQL file.
set -eu
: "${POSTGRES_PORTAL_PASSWORD:?POSTGRES_PORTAL_PASSWORD not set}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOF'
\getenv pw POSTGRES_PORTAL_PASSWORD
ALTER ROLE portal PASSWORD :'pw';
EOF
