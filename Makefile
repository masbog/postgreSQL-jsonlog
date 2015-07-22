MODULES = jsonlog
PG_CONFIG = /usr/pgsql-9.4/bin/pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
