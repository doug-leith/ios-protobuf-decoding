"""URL → decoder dispatch for known Apple endpoints.

The original addon had two parallel dicts (``request_decoders`` / ``response_decoders``)
of URL-regex → a hand-written ``decode_apple_*`` function, and almost every one of
those functions did the same three things: strip the ARPC header, decode the body
against one ``(schema_file, MessageName)``, and fall back to a raw protobuf decode.

Here that pattern is **data**.  An :class:`Endpoint` names a URL regex plus a request
and/or response :class:`Rule`; a Rule is either a declarative protobuf rule
(``schema_file`` + ``message`` + ``framing``) or a custom callable for the handful of
genuinely odd endpoints.  Generic ARPC/plain protobuf fallbacks cover anything
unlisted, so adding an endpoint is usually one line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from . import arpc, fb, tiles               # fb/tiles are the rule providers for the table
# The rule INTERFACE lives one layer down, in .rules, so fb/tiles can supply rules without
# importing this module back -- which is what used to force the fb/tiles import into a
# function body here.  DecodeContext/Rule/decode_arpc_or_raw are re-exported because this is
# where the table that consumes rules lives, and the reporter, the decoder and the tests
# already import them from `endpoints`.
from .rules import (                        # noqa: F401  (re-export)
    DecodeContext,
    Rule,
    decode_arpc_or_raw,
)
from .rules import _decode_schema_rule      # used by the two wloc routers below

__all__ = ["Endpoint", "Rule", "DecodeContext", "EndpointTable", "default_table",
           "decode_arpc_or_raw"]


@dataclass
class Endpoint:
    """A URL pattern and the rule(s) for its request / response bodies."""
    pattern: str
    request: Optional[Rule] = None
    response: Optional[Rule] = None

    def __post_init__(self) -> None:
        self._re = re.compile(self.pattern)

    def matches(self, url: str) -> bool:
        return self._re.search(url) is not None


# --- the generic decoders that the declarative rules build on ----------------

def decode_generic_arpc_request(body: bytes, ctx: DecodeContext) -> str:
    """Strip an ARPC request header (if any) and raw-decode the payload."""
    return decode_arpc_or_raw(body, "arpc_request")


def decode_generic_arpc_response(body: bytes, ctx: DecodeContext) -> str:
    """Strip an ARPC response header (if any) and raw-decode the payload."""
    return decode_arpc_or_raw(body, "arpc_response")


# --- wloc: locationd ALS multiplexes message types by ARPC functionId --------
#
# gs-loc.apple.com/clls/wloc carries more than one message on the same URL, keyed by
# the ARPC request functionId (the response header echoes it as responseType):
#   fid 1 -> ALSLocationRequest  / ALSLocationResponse   (cell-tower positioning)
#   fid 3 -> ALSNearbyRequest    / ALSNearbyResponse      (lat/lng -> nearby WiFi APs)
# Wire-confirmed: a fid-3 request carries latitude(1)/longitude(2)/meta(35) — exactly
# ALSNearbyRequest's layout, where meta is field 35 (it is field 33 in ALSLocationRequest,
# which is why those fields read as "unknown" when the whole URL was mapped to one message)
# — and replies with repeated ALSWirelessAP = ALSNearbyResponse. Route on the id so each
# decodes against its real schema instead of flagging the other type's fields as unknown.
_WLOC_REQUEST_BY_FID = {1: "als.ALSLocationRequest", 3: "als.ALSNearbyRequest"}
_WLOC_RESPONSE_BY_TYPE = {1: "als.ALSLocationResponse", 3: "als.ALSNearbyResponse"}


def decode_wloc_request(body: bytes, ctx: DecodeContext) -> str:
    """Decode a /clls/wloc request against the ALS message its functionId selects."""
    hdr = arpc.parse_request_header(body)
    message = _WLOC_REQUEST_BY_FID.get(hdr.function_id) if hdr else None
    if message is None:                      # unmapped/absent functionId -> raw, with the header
        return decode_generic_arpc_request(body, ctx)
    return _decode_schema_rule(Rule("als.proto", message, "arpc_request"), body, ctx)


def decode_wloc_response(body: bytes, ctx: DecodeContext) -> str:
    """Decode a /clls/wloc response against the ALS message its responseType selects."""
    hdr = arpc.parse_response_header(body)
    message = _WLOC_RESPONSE_BY_TYPE.get(hdr.response_type) if hdr else None
    if message is None:
        return decode_generic_arpc_response(body, ctx)
    return _decode_schema_rule(Rule("als.proto", message, "arpc_response"), body, ctx)


# --- the endpoint table ------------------------------------------------------

# Schema files are the UNMODIFIED apple_protobuf_extractor output committed under
# ios_decoder/protos/<Framework>/ (GeoServices→geo.proto package "geo" with the GEO
# prefix stripped; locationd→als.proto package "als"; CoreLocationProtobuf→clp.proto
# package "clp" with the CLP prefix stripped). Messages are package-qualified.
_GEO = "geo.proto"

# bytes fields that hold another protobuf, for Rule(embedded=...): both traffic-probe log events
# carry a locationd CLPLocationCollectionRequest (clp.proto, package "clp") in `locationCollection`.
_TRAFFIC_PROBE_EMBEDDED = {
    "geo.LogMsgEventRealtimeTrafficProbe.locationCollection":
        ("clp.proto", "clp.LocationCollectionRequest"),
    "geo.LogMsgEventBatchTrafficProbe.locationCollection":
        ("clp.proto", "clp.LocationCollectionRequest"),
}


def _build_default_endpoints() -> list[Endpoint]:
    """The known GeoServices / locationd protobuf + tile endpoints, ported from the addon."""
    # `fb` and `tiles` are imported at module level now that the rule interface lives in
    # .rules and they no longer import this module back.  These three are deferred only for
    # table-construction locality; there is no cycle to break.
    from . import certs, iad, telemetry
    raw_req = Rule(handler=decode_generic_arpc_request)    # strips the ARPC *request* header
    raw_resp = Rule(handler=decode_generic_arpc_response)  # strips the ARPC *response* header
    cert_rule = Rule(handler=lambda b, c: certs.decode_certificates(b))

    def tile(name):
        return Rule(handler=tiles.tile_rule(name).handler)

    iad_rule = Rule(handler=lambda b, c: iad.decode_iad(b))
    xp_rule = Rule(handler=telemetry.decode_xp)
    amp_rule = Rule(handler=telemetry.decode_amp)

    return [
        # --- requests + responses that have a named schema ---
        Endpoint(r"gs-loc\.apple\.com/clls/wloc",
                 Rule(handler=decode_wloc_request),     # routes on functionId (1=Location, 3=Nearby)
                 Rule(handler=decode_wloc_response)),   # routes on responseType
        Endpoint(r"gsp[0-9]+-ssl\.apple\.com/hcy/pbcwloc",
                 Rule("clp.proto", "clp.CellWifiCollectionRequest", "arpc_request"),
                 Rule("clp.proto", "clp.CellWifiCollectionResponse", "arpc_response")),
        Endpoint(r"gsp[0-9]+-ssl\.ls\.apple\.com/wifi_request",
                 Rule(_GEO, "geo.WiFiQualityServiceRequest", "arpc_request"),
                 Rule(_GEO, "geo.WiFiQualityServiceResponse", "arpc_response")),
        Endpoint(r"gspe[0-9]+-ssl\.ls\.apple\.com/wifi_request_tile",
                 None,
                 Rule(_GEO, "geo.WiFiQualitySearchResultTile", "plain")),
        Endpoint(r"gsp-ssl\.ls\.apple\.com/ab\.arpc",
                 Rule(_GEO, "geo.ABAssignmentRequest", "arpc_request"),
                 Rule(_GEO, "geo.ABAssignmentResponse", "arpc_response")),
        Endpoint(r"gsp-ssl\.ls\.apple\.com/dispatcher\.arpc",
                 Rule(_GEO, "geo.PDPlaceRequest", "arpc_request"),
                 Rule(_GEO, "geo.PDPlaceResponse", "arpc_response")),
        Endpoint(r"gsp[0-9]+-ssl-revgeo\.ls\.apple\.com/dispatcher\.arpc",
                 Rule(_GEO, "geo.PDPlaceRequest", "arpc_request"),
                 Rule(_GEO, "geo.PDPlaceResponse", "arpc_response")),
        # The background dispatcher (manifest field backgroundDispatcherURL, URL type 34): the
        # only request config that can select it is GEOPlaceDataRequestConfig, i.e. PDPlaceRequest.
        # No capture contains this host yet; the rule is from the GeoServices disassembly.
        Endpoint(r"gsp[0-9]+-ssl-background\.ls\.apple\.com/dispatcher\.arpc",
                 Rule(_GEO, "geo.PDPlaceRequest", "arpc_request"),
                 Rule(_GEO, "geo.PDPlaceResponse", "arpc_response")),
        # The "BluePOI" dispatcher (manifest field bluePOIDispatcherURL).  geod sends the
        # Wi-Fi-fingerprint lookup (PDPlaceRequest requestType WIFI_FINGERPRINT_LOOKUP) here.
        Endpoint(r"gsp[0-9]+-ssl-locus\.ls\.apple\.com/dispatcher\.arpc",
                 Rule(_GEO, "geo.PDPlaceRequest", "arpc_request"),
                 Rule(_GEO, "geo.PDPlaceResponse", "arpc_response")),
        # photoanalysisd (Photos analysis) calls the geo servers directly, not through geod, via
        # MediaMiningKit (which links GeoServices).  Both URLs come from the geo_manifest.
        #  - batch_reverse_geocoder_place_request_url (seen: gsp36 revgeo_pr.arpc): a PDPlaceRequest
        #    of requestType BATCH_REVERSE_GEOCODING, the photo locations in
        #    batchReverseGeocodingParameters.assetLocations.  MediaMiningKit's
        #    -[CLSLocationQueryPerformer initWithRegions:precision:] calls GEOMapService
        #    ticketForBatchReverseGeocodeLocations:...
        #  - spatial_lookup_url (seen: gsp51 api/v1.0/poi/data, ARPC requestType 1021): a
        #    SpatialLookupBatchRequest (centre, radius, categories), not a PDPlaceRequest.
        #    -[CLSBusinessItemGenericQueryPerformer initWithRegions:categories:precision:] calls
        #    ticketForSpatialLookupParameters:traits:.
        Endpoint(r"gsp[0-9]+-ssl\.ls\.apple\.com/revgeo_pr\.arpc",
                 Rule(_GEO, "geo.PDPlaceRequest", "arpc_request"),
                 Rule(_GEO, "geo.PDPlaceResponse", "arpc_response")),
        Endpoint(r"gsp[0-9]+-ssl\.ls\.apple\.com/api/v1\.0/poi/data",
                 Rule(_GEO, "geo.SpatialLookupBatchRequest", "arpc_request"),
                 Rule(_GEO, "geo.SpatialLookupBatchResponse", "arpc_response")),
        # Protobuf resources that geod downloads from the URLs in the geo_manifest.  Matched by the
        # resource file name, the GeoServices class of the same name, and the wire fit (no unknown
        # fields for LPRWorld; 3 nested unknowns for SearchAttributionManifest).  The two
        # publisher_attribution_*.pb files hold protobuf map<> fields (publisher id -> source /
        # file index); the Extractor recovers them as map<string, ...>, so every entry is shown
        # (a map field it could only emit as a singular bytes field would keep just the last one).
        Endpoint(r"gspe[0-9]+-ssl\.ls\.apple\.com/config/search-attribution-[0-9]+",
                 None,
                 Rule(_GEO, "geo.SearchAttributionManifest", "plain")),
        Endpoint(r"gspe[0-9]+-ssl\.ls\.apple\.com/other/publisher_attribution_dot_coms-[0-9]+\.pb",
                 None,
                 Rule(_GEO, "geo.PublisherAttributionManifest", "plain")),
        Endpoint(r"gspe[0-9]+-ssl\.ls\.apple\.com/other/publisher_attribution_manifest_index-[0-9]+\.pb",
                 None,
                 Rule(_GEO, "geo.PublisherAttributionManifestIndex", "plain")),
        Endpoint(r"gspe[0-9]+-ssl\.ls\.apple\.com/other/regional_vehicle_info-[0-9]+\.pb",
                 None,
                 Rule(_GEO, "geo.LPRWorld", "plain")),
        Endpoint(r"gspe[0-9]+-ssl\.ls\.apple\.com/geo_manifest/dynamic/config",
                 None,
                 Rule(_GEO, "geo.Resources", "plain")),

        # --- locationd's "harvest" uploads: CoreLocationProtobuf *CollectionRequest ---
        # The ARPC requestType on the wire is the request class's requestTypeCode:
        # LocationCollection 101 (/pds/pd), TraceCollection 109 (/hvr/trc), CellWifiCollection 100
        # (/hcy/pbcwloc, above).  /psr is the exception: its requests carry requestType 0 (the
        # class's requestTypeCode is 106), but the body is exactly PressureCollectionRequest
        # (meta, pressure, pressureLocation).  Responses are CollectionResponse {success, msg}: a 2-byte
        # `1: 1` acknowledgement for /hcy/pbcwloc and /pds/pd, empty for /hvr/trc and /psr.
        Endpoint(r"gsp[0-9]+-ssl\.apple\.com/pds/pd",
                 Rule("clp.proto", "clp.LocationCollectionRequest", "arpc_request"),
                 Rule("clp.proto", "clp.LocationCollectionResponse", "arpc_response")),
        Endpoint(r"gsp[0-9]+-ssl\.apple\.com/hvr/trc",
                 Rule("clp.proto", "clp.TraceCollectionRequest", "arpc_request"),
                 Rule("clp.proto", "clp.TraceCollectionResponse", "arpc_response")),
        Endpoint(r"gsp[0-9]+-ssl\.apple\.com/psr",
                 Rule("clp.proto", "clp.PressureCollectionRequest", "arpc_request"),
                 Rule("clp.proto", "clp.PressureCollectionResponse", "arpc_response")),

        # --- geod's log-message uploads: GEOLogMessageCollectionRequest ---
        # Both URLs carry ARPC functionId 1017, which is what
        # -[GEOLogMessageCollectionRequest requestTypeCode] returns (0x3f9), and the response class
        # is GEOLogMessageCollectionResponse.  The manifest names them: logMessageUsageV3URL and the
        # four analytics{Cohort,Long,Short,Sessionless}SessionURL fields (all .../hvr/v3/use) and
        # realtimeTrafficProbeURL (.../hvr/v2/rtloc; batchTrafficProbeURL, .../hvr/v2/loc, is the
        # unobserved batch counterpart).  The traffic-probe events hold a CoreLocationProtobuf
        # LocationCollectionRequest in the bytes field `locationCollection`.
        Endpoint(r"gsp[0-9]+-ssl\.ls\.apple\.com/hvr/v3/use",
                 Rule(_GEO, "geo.LogMessageCollectionRequest", "arpc_request",
                      embedded=_TRAFFIC_PROBE_EMBEDDED),
                 Rule(_GEO, "geo.LogMessageCollectionResponse", "arpc_response")),
        Endpoint(r"gsp[0-9]+-ssl\.apple\.com/hvr/v2/rtloc",
                 Rule(_GEO, "geo.LogMessageCollectionRequest", "arpc_request",
                      embedded=_TRAFFIC_PROBE_EMBEDDED),
                 Rule(_GEO, "geo.LogMessageCollectionResponse", "arpc_response")),

        # --- ARPC endpoints we strip + raw-decode (no dedicated schema) ---

        # --- iAd advertising SDK (8-byte header + raw protobuf) ---
        Endpoint(r"iadsdk\.apple\.com/adserver/2\.6/optout/optout_optin",
                 iad_rule, iad_rule),
        Endpoint(r"iadsdk\.apple\.com/adserver/2\.6/segment/update",
                 iad_rule, iad_rule),
        Endpoint(r"tr\.iadsdk\.apple\.com/adserver/2\.6/settings", None, iad_rule),
        Endpoint(r"cf\.iadsdk\.apple\.com/adserver/2\.6/config", None, iad_rule),

        # --- parsecd feedback upload: polymorphic by ?type= (per-channel message) ---
        Endpoint(r"(fbs|api)\.smoot\.apple\.com/fb\b",
                 Rule(handler=fb.decode_fb), None),

        # --- XP / AMP ad telemetry (nested JSON; base64/protobuf expanded) ---
        Endpoint(r"xp\.apple\.com/report/", xp_rule, None),
        Endpoint(r"amp-api[\w-]*\.apps\.apple\.com/v1/engagement", amp_rule, amp_rule),

        # --- X.509 certificate responses ---
        Endpoint(r"humb\.apple\.com/humbug/baa", None, cert_rule),          # PEM chain
        Endpoint(r"swallow\.apple\.com/.*GetCertificate", None, cert_rule),  # DER chain

        # --- binary tile responses (decoded via the uniform tile adapters) ---
        Endpoint(r"cl3\.apple\.com/1/v2/clsef\.bin\.gz", None, tile("clsef")),
        Endpoint(r"cl3\.apple\.com/3/v2/cldavl\.avl\.gz", None, tile("cldavl")),
        Endpoint(r"cl2\.apple\.com/1/v1/[0-9]+", None, tile("wifi")),
        Endpoint(r"cl3\.apple\.com/2/v1/[0-9]+", None, tile("hrse")),
        Endpoint(r"cl2\.apple\.com/3/v1/[0-9]+", None, tile("gsmcell")),
        Endpoint(r"cl3\.apple\.com/3/v2/[0-9]+", None, tile("cldem")),
        Endpoint(r"cl2\.apple\.com/4/v1/[0-9]+", None, tile("ltecell")),
        Endpoint(r"cl2\.apple\.com/6/v1/[0-9]+", None, tile("global_gsm")),
        Endpoint(r"cl2\.apple\.com/7/v1/[0-9]+", None, tile("global_cdma")),
        Endpoint(r"cl2\.apple\.com/8/v1/[0-9]+", None, tile("global_lte")),
        Endpoint(r"cl2\.apple\.com/11/v1/[0-9]+", None, tile("global_5g")),
    ]


class EndpointTable:
    """Ordered list of :class:`Endpoint`; resolves a URL to a request/response Rule."""

    def __init__(self, endpoints: list[Endpoint]):
        self.endpoints = endpoints

    def request_rule(self, url: str) -> Optional[Rule]:
        for ep in self.endpoints:
            if ep.request is not None and ep.matches(url):
                return ep.request
        return None

    def response_rule(self, url: str) -> Optional[Rule]:
        for ep in self.endpoints:
            if ep.response is not None and ep.matches(url):
                return ep.response
        return None


def default_table() -> EndpointTable:
    """The built-in endpoint table covering the known GeoServices/locationd APIs."""
    return EndpointTable(_build_default_endpoints())
