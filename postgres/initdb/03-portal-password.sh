#!/bin/sh
# Runs once, when the database volume is empty (after 02-schema.sql has created the role "portal").
sh /migrations/002-portal-password.sh