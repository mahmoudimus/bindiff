"""The IDA-side half of the BinDiff plugin.

Present so this is a regular package and can be named in a wheel. IDA itself
does not import it this way -- it loads bindiff_plugin.py by path, as a
top-level script with no parent package, which is what
test_plugin_loads_the_way_ida_loads_it checks.
"""
