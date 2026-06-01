"""Tool registry loader.

Importing this module side-effects-registers every TypedTool subclass via the
@register_tool decorator. Anything depending on the catalog (the MCP server,
the CLI `sworn tools list`, the eval harness) imports this once at startup.
"""

# Imports for side effects (decorator-based registration).
from sworn.tools import (  # noqa: F401
    bulk_extractor,
    evtx,
    hindsight,
    mft,
    pecmd,
    plaso,
    regripper,
    sleuthkit,
    volatility,
    yara,
)
from sworn.tools._base import iter_tools, get_tool

__all__ = ["iter_tools", "get_tool"]
