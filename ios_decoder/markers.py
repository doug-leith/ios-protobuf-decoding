"""Analysis markers — the ``+++TAG …`` lines downstream scripts grep + awk-parse.

These lines are a machine-read interface, so they must be a **single, stable, documented
format** — not scattered ``print(f"+++…")`` calls that can drift apart.  This module owns
that format: markers are constructed as :class:`Marker` *values* through named constructors
(each constructor's signature defines the field layout = the awk contract), collected in a
:class:`MarkerSink`, and emitted in one place by the reporter.

Line format (greppable with ``grep '^+++'``):

    +++<TAG> <field> <field> ...

Fields are space-separated; coordinate groups are a parenthesized tuple, e.g.::

    +++XYZ wifi_tile (142,172,5)
    +++LATLON gs-loc (53.41,-7.38)
    +++LATLON_BOUNDBOX cldem_tile (52.0,54.0,-8.0,-6.0)

To add a marker family, add a constructor here (don't format ``+++`` strings elsewhere).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

__all__ = ["Marker", "MarkerSink", "xyz", "latlon", "boundbox", "custom",
           "request", "reqheaders"]


@dataclass(frozen=True)
class Marker:
    """One ``+++`` analysis line: a tag plus ordered, already-formatted fields."""
    tag: str
    fields: tuple[object, ...] = ()

    def line(self) -> str:
        """Render the canonical single-line form (no trailing newline)."""
        if not self.fields:
            return f"+++{self.tag}"
        return f"+++{self.tag} " + " ".join(str(f) for f in self.fields)

    def __str__(self) -> str:  # so str(marker) and print(marker) just work
        return self.line()


# --- constructors: one per family; the args ARE the awk field contract --------

def xyz(source: str, x, y, z) -> Marker:
    """``+++XYZ <source> (x,y,z)`` — a tile/grid coordinate triple."""
    return Marker("XYZ", (source, f"({x},{y},{z})"))


def latlon(source: str, lat, lon) -> Marker:
    """``+++LATLON <source> (lat,lon)`` — a single decoded point."""
    return Marker("LATLON", (source, f"({lat},{lon})"))


def boundbox(source: str, lat_min, lat_max, lon_min, lon_max) -> Marker:
    """``+++LATLON_BOUNDBOX <source> (lat_min,lat_max,lon_min,lon_max)`` — a tile's extent."""
    return Marker("LATLON_BOUNDBOX", (source, f"({lat_min},{lat_max},{lon_min},{lon_max})"))


def custom(tag: str, *fields) -> Marker:
    """Escape hatch for a one-off marker family not yet given its own constructor."""
    return Marker(tag, tuple(fields))


def request(url: str, content_length: int, timestamp) -> Marker:
    """``+++REQUEST <url> <content_length> <timestamp>`` — one per request flow."""
    return Marker("REQUEST", (url, content_length, timestamp))


def reqheaders(url: str, user_agent: str, headers: str) -> Marker:
    """``+++REQHEADERS <url> € <user_agent> € <headers>`` — ``€`` separates the
    structured fields (the ``headers`` field itself uses ``~`` between key=value pairs)."""
    return Marker("REQHEADERS", (url, "€", user_agent, "€", headers))


# --- collection ---------------------------------------------------------------

@dataclass
class MarkerSink:
    """Collects markers produced while decoding, so the reporter emits them in one place
    instead of decoders printing ``+++`` lines ad hoc."""
    _markers: list[Marker] = field(default_factory=list)

    def emit(self, *markers: Marker) -> None:
        """Add one or more markers to the sink."""
        self._markers.extend(markers)

    def clear(self) -> None:
        """Drop all collected markers (the reporter resets the sink per flow)."""
        self._markers.clear()

    def lines(self) -> list[str]:
        """The collected markers as canonical ``+++`` lines, in emission order."""
        return [m.line() for m in self._markers]

    def __iter__(self) -> Iterator[Marker]:
        return iter(self._markers)

    def __len__(self) -> int:
        return len(self._markers)

    def __bool__(self) -> bool:
        return bool(self._markers)
