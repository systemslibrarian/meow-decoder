"""
meow_decoder._archive — Archived (non-production) modules.

These modules are NOT importable from production code.  They were moved
here because static + dynamic analysis showed they are unreachable from
the production entrypoints (encode.py, decode_gif.py, deadmans_switch_cli.py).

To restore a module to production, move it back to meow_decoder/ and
re-run the import-graph analysis.
"""

raise ImportError(
    "meow_decoder._archive is an archive of non-production modules. "
    "Importing from it is forbidden. If you need a module that was "
    "archived, move it back to meow_decoder/ and verify it is reachable "
    "from the production entrypoints."
)
