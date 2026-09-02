"""The one place that reaches into IDA.

IDA exposes the same functions twice: as `ida_frame.get_func_frame` and as
`idaapi.get_func_frame`, because `idaapi` is a facade that re-exports the
`ida_*` modules. Measured across both supported builds, it carries
essentially all of it -- 43 of 43 names this package uses on 9.4, 42 of 43 on
9.1, the odd one out being `get_func_ea_by_num`, which is 9.4's replacement
for `getn_func` and does not exist on 9.1 at all.

Going through one facade is what makes a version difference fixable in one
place instead of wherever it happens to bite. Two are already known:

  * `get_func_frame` and `calc_stkvar_struc_offset` are deprecated on 9.4 in
    favour of `*_ea` spellings that 9.1 does not have. The warnings fire on
    every call, so following them is the obvious move and it breaks the
    compatibility leg.
  * `getn_func` is deprecated on 9.4 for `get_func_ea_by_num`, same story.

`entry_points()` below is what a backport looks like here: the caller asks
for function entry points and does not learn which spelling answered.

**The import is deferred, and has to be**, for two separate reasons.

`idaapi` does `from ida_ida import *`, and `ida_ida` evaluates database state
at import time -- with no database open that is not an ImportError but INTERR
3123, which asks you to restart IDA.

And in an idalib process `idapro` must be imported *first*: it loads
libidalib and libida with global symbols before `ida_pro` imports
`_ida_pro`. Importing `idaapi` ahead of it is "Fatal error before kernel
init" on 9.1 -- fatal to the process, not an exception the caller can catch.
9.4 tolerates it, so a 9.4-only run will not show you the bug.

So `api()` refuses rather than importing when neither has happened: the GUI
is recognised by IDA's own start-up having loaded `ida_kernwin`, and a
worker by `idapro` already being in `sys.modules`. It never imports `idapro`
itself -- which of the two a process is, is the caller's decision and
`bindiff.headless` makes it deliberately.
"""

from __future__ import annotations

from typing import Any, Callable, List, Optional


class Unavailable(Exception):
    """This IDA does not expose an API this package needs."""


_api = None


def api():
    """The `idaapi` facade, imported on first use.

    Cached after the first success, because the failure mode is loud and the
    success is permanent.

    Refuses to import into a process that has established neither kernel.
    See the module docstring: getting this wrong is a fatal error rather than
    an exception, so it is checked instead of attempted.
    """
    global _api
    if _api is None:
        _require_a_kernel()
        try:
            import idaapi
        except ImportError as exc:
            raise Unavailable(f"IDA is not importable here: {exc}") from exc
        _api = idaapi
    return _api


def _require_a_kernel() -> None:
    """Refuse before an import that would take the process down.

    Two shapes are safe. Inside the GUI, IDA's own start-up has already
    imported `ida_kernwin`, so the kernel is up and `idapro` must *not* be
    imported. In a worker, `idapro` has been imported and has loaded libida
    with global symbols, which is what makes the rest of the modules work.

    Anything else -- a plain interpreter, or a worker that has not imported
    `idapro` yet -- gets a sentence rather than "Fatal error before kernel
    init".
    """
    import sys

    if "ida_kernwin" in sys.modules or "idapro" in sys.modules:
        return
    raise Unavailable(
        "IDA's kernel is not up in this process. Inside IDA this cannot "
        "happen; in a worker, import idapro and open a database before "
        "anything reaches for the API -- importing it first is what loads "
        "libida, and going the other way is a fatal error rather than an "
        "ImportError.")


def module(name: str):
    """One of the `ida_*` modules, for the few things the facade omits.

    Prefer `api()`. This exists so that reaching past the facade is still a
    call into this module, and therefore still findable.
    """
    import importlib

    _require_a_kernel()
    try:
        return importlib.import_module(name)
    except ImportError as exc:
        raise Unavailable(f"{name} is not importable here: {exc}") from exc


def first_available(*names: str) -> Callable:
    """The first of `names` this build has.

    Named spellings in preference order, oldest-compatible first. A build
    with none of them fails with a sentence rather than an AttributeError
    halfway through a diff.
    """
    facade = api()
    for name in names:
        found = getattr(facade, name, None)
        if found is not None:
            return found
    raise Unavailable(
        f"idaapi has none of {', '.join(names)}; the API has moved and "
        "bindiff.ida needs updating")


def available(*names: str) -> bool:
    """Whether this build has all of `names`, without raising."""
    try:
        facade = api()
    except Unavailable:
        return False
    return all(getattr(facade, name, None) is not None for name in names)


def constant(name: str, default: Any = None) -> Any:
    """A named constant, or `default` where the build has no such name."""
    return getattr(api(), name, default)


# -- backports ---------------------------------------------------------------
#
# Where the two builds disagree, the difference is resolved here and the
# caller asks for what it wants rather than for a spelling.

def entry_points(limit: Optional[int] = None) -> List[int]:
    """Every function's entry address.

    9.4 deprecates `getn_func` for `get_func_ea_by_num`, which 9.1 does not
    have. Asking for the newer one first and falling back keeps the warning
    off 9.4 without breaking 9.1.
    """
    facade = api()
    count = facade.get_func_qty()
    if limit is not None:
        count = min(count, limit)

    by_number = getattr(facade, "get_func_ea_by_num", None)
    if by_number is not None:
        found = [by_number(index) for index in range(count)]
    else:
        found = []
        for index in range(count):
            function = facade.getn_func(index)
            if function is not None:
                found.append(function.start_ea)
    bad = facade.BADADDR
    return [address for address in found if address not in (None, bad)]


def frame_of(function):
    """A function's frame as a tinfo_t, or None when it has none.

    `get_func_frame` is deprecated on 9.4 for `get_func_frame_ea`, which 9.1
    does not have, so the un-suffixed spelling is the one to ask for.
    """
    facade = api()
    frame = facade.tinfo_t()
    getter = first_available("get_func_frame")
    if not getter(frame, function):
        return None
    return frame


def stack_offset(function, instruction, operand_index: int) -> Optional[int]:
    """The frame offset an operand refers to, or None if it refers to none.

    Refuses more than BADADDR. On both builds this returns values outside the
    frame -- 97 of them over one binary on 9.4, 5 over one function on 9.1 --
    and multiplying one by 8 for a bit offset raises OverflowError rather
    than failing the lookup.
    """
    facade = api()
    calc = first_available("calc_stkvar_struc_offset")
    try:
        offset = calc(function, instruction, operand_index)
    except Exception:
        return None
    if offset == facade.BADADDR:
        return None
    frame = frame_of(function)
    if frame is None or not 0 <= offset < frame.get_size():
        return None
    return offset


def decompiler():
    """`idaapi` with Hex-Rays initialised, or None where there is none.

    Hex-Rays is licensed separately. `init_hexrays_plugin` is what says
    whether it is *usable*, as against importable: the module imports in an
    install without a licence and every call then fails.
    """
    try:
        facade = api()
    except Unavailable:
        return None
    initialise = getattr(facade, "init_hexrays_plugin", None)
    if initialise is None:
        return None
    try:
        if not initialise():
            return None
    except Exception:
        return None
    return facade
