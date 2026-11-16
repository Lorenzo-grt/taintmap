"""Regenerate the catalog JSON schemas: ``python -m taintmap.catalog``."""

from taintmap.catalog import write_schemas

for path in write_schemas():
    print(path)
