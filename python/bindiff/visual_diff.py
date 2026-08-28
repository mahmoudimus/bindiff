"""Talking to the BinDiff Java UI.

The UI listens on a TCP socket (127.0.0.1:2000 by default) and accepts one
message per connection: a 4-byte length prefix in the host's native byte order,
followed by an XML payload. That is the whole protocol -- see
DoSendGuiMessageTCP in ida/visual_diff.cc and VisualDiffMessage in
ida/results.cc.

Reimplemented here rather than bound, so the plugin can open a graph view
without going through the C++ plugin. ResultsWrapper::PrepareVisualDiff used to
answer this with "Visual diff not available in standalone mode".
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional
from xml.sax.saxutils import quoteattr

DEFAULT_SERVER = "127.0.0.1"
DEFAULT_PORT = 2000

# The C++ side writes the length by reinterpreting a uint32_t, so it is native
# byte order rather than network order. "=I" matches that; "!I" would not.
_LENGTH_PREFIX = "=I"


@dataclass(frozen=True)
class VisualDiffRequest:
    """Everything the UI needs to open one match.

    `database` is the .BinDiff file, and the two paths are the .BinExport
    inputs it was produced from -- the UI reads all three.
    """

    database: str
    primary_path: str
    primary_address: int
    secondary_path: str
    secondary_address: int
    call_graph: bool = False

    def to_xml(self) -> str:
        """Builds the message the UI parses.

        Attribute values are quoted properly rather than interpolated: a path
        containing a quote character would otherwise produce malformed XML that
        the UI silently fails to parse. Note the engine emits `path =` with a
        space for the Database element; that spelling is kept because it is
        what the UI accepts.
        """
        kind = "call_graph" if self.call_graph else "flow_graph"
        return (
            f"<BinDiffMatch type={quoteattr(kind)}>"
            f"<Database path ={quoteattr(self.database)}/>"
            f"<Primary path={quoteattr(self.primary_path)}"
            f" address={quoteattr(str(self.primary_address))}/>"
            f"<Secondary path={quoteattr(self.secondary_path)}"
            f" address={quoteattr(str(self.secondary_address))}/>"
            f"</BinDiffMatch>"
        )


def encode_message(message: str) -> bytes:
    """Frames a message: native-order uint32 length, then UTF-8 payload."""
    payload = message.encode("utf-8")
    return struct.pack(_LENGTH_PREFIX, len(payload)) + payload


def send_gui_message(message: str, server: str = DEFAULT_SERVER,
                     port: int = DEFAULT_PORT,
                     timeout: Optional[float] = 5.0) -> None:
    """Sends one message to a running UI.

    Raises ConnectionError when no UI is listening. Starting one is deliberately
    not attempted here: the engine's SendGuiMessage launches the Java UI and
    then retries for up to twenty seconds, which is not something to do behind
    the caller's back on a UI thread. Call this, catch the error, and decide.
    """
    try:
        with socket.create_connection((server, port), timeout=timeout) as sock:
            sock.sendall(encode_message(message))
    except OSError as exc:
        raise ConnectionError(
            f"no BinDiff UI listening on {server}:{port} ({exc})") from exc


def send_visual_diff(request: VisualDiffRequest,
                     server: str = DEFAULT_SERVER,
                     port: int = DEFAULT_PORT) -> None:
    send_gui_message(request.to_xml(), server=server, port=port)
