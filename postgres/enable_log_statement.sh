#!/bin/sh
set -x

PGCONF=/var/lib/postgresql/data/postgresql.conf
sed -i "s/#log_statement = 'none'.*/log_statement = 'all'/g" $PGCONF
