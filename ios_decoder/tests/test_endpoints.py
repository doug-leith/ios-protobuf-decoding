"""Endpoint dispatch: declarative rules, the partial-schema note, and safe fallback."""

import pytest

from ios_decoder.endpoints import DecodeContext, Rule, default_table
from ios_decoder.schemas import SchemaError, SchemaRegistry
from ._arpc_fixtures import build_request, build_response, PROTOBUF_150


def test_missing_protoc_raises_schemaerror(tmp_path):
    # the most likely portability failure on a fresh host: protoc absent must raise a clear
    # SchemaError (which the rule path catches -> raw fallback), never an opaque crash
    (tmp_path / "x.proto").write_text('syntax = "proto3";\nmessage X { int32 a = 1; }\n')
    reg = SchemaRegistry([tmp_path], cache_dir=tmp_path / "cache", protoc="/nonexistent/protoc")
    with pytest.raises(SchemaError, match="protoc not found"):
        reg.message_class("x.proto", "X")


class StubSchemas:
    """Stand-in for SchemaRegistry so endpoint logic is tested without protoc."""

    def __init__(self, result=None, error=None):
        self.result = result if result is not None else ("decoded: 1\n", [], 0)
        self.error = error

    def decode_with_coverage(self, proto_file, message, data, embedded=None):
        if self.error is not None:
            raise self.error
        return self.result


def _ctx(**kw):
    return DecodeContext(schemas=StubSchemas(**kw))


def test_schema_rule_emits_header_and_body():
    rule = Rule("x.proto", "M", "arpc_request")
    body = build_request(app="com.apple.geod", payload=PROTOBUF_150)
    out = rule.decode(body, _ctx())
    assert "apple arpc header" in out
    assert "decoded: 1" in out


def test_partial_schema_is_announced():
    rule = Rule("x.proto", "M", "arpc_request")
    body = build_request(payload=PROTOBUF_150)
    out = rule.decode(body, _ctx(result=("decoded: 1\n", [7, 42], 0)))
    assert "// note:" in out
    assert "2 top-level" in out and "7, 42" in out


def test_partial_schema_announces_nested_unknowns():
    # unknowns hidden inside a known sub-message must be flagged too (not just top-level)
    rule = Rule("x.proto", "M", "arpc_request")
    body = build_request(payload=PROTOBUF_150)
    out = rule.decode(body, _ctx(result=("decoded: 1\n", [], 3)))
    assert "// note:" in out and "3 inside known sub-message(s)" in out


def test_hvr_use_request_uses_request_framing():
    # regression: hvr/v3/use + hvr/v2/rtloc REQUESTS are ARPC-request-framed; the table used
    # response framing for both directions, so requests failed to strip -> "undecodable".
    from ios_decoder.decode import decode_request_body
    body = build_request(app="com.apple.geod", payload=PROTOBUF_150)
    ctx = DecodeContext(schemas=StubSchemas())
    for url in ("https://gsp64-ssl.ls.apple.com/hvr/v3/use",
                "https://gsp9-ssl.apple.com/hvr/v2/rtloc"):
        out = decode_request_body(url, body, default_table(), ctx)
        assert "apple arpc header" in out and "decoded: 1" in out   # stripped, then schema-decoded
        assert "undecodable" not in out


def test_full_schema_has_no_note():
    rule = Rule("x.proto", "M", "arpc_request")
    out = rule.decode(build_request(payload=PROTOBUF_150), _ctx(result=("ok\n", [], 0)))
    assert "// note:" not in out


def test_schema_failure_falls_back_to_raw_and_warns():
    rule = Rule("x.proto", "M", "arpc_request")
    body = build_request(payload=PROTOBUF_150)
    out = rule.decode(body, _ctx(error=SchemaError("nope")))
    assert "// WARNING: schema decode failed" in out
    assert "1: 150" in out  # safe fallback actually decoded the bytes


def test_schema_and_raw_both_fail_is_an_error_line():
    rule = Rule("x.proto", "M", "plain")
    # truncated length-delimited field -> raw decode also fails
    out = rule.decode(bytes.fromhex("0a"), _ctx(error=SchemaError("nope")))
    assert "// ERROR:" in out


def test_plain_text_sentinel_shown_not_errored():
    # a tile server's literal "Not Found" must render as text, not a protobuf error
    rule = Rule("geo.proto", "geo.WiFiQualitySearchResultTile", "plain")
    out = rule.decode(b"Not Found", _ctx(error=SchemaError("corrupt")))
    assert "plain-text body" in out and "Not Found" in out
    assert "ERROR" not in out and "WARNING" not in out


def test_text_sentinel_gate():
    from ios_decoder import rules            # the sentinel gate lives with the rule interface
    assert rules._text_sentinel(b"Not Found") == "Not Found"
    # a *valid* protobuf that is also all-printable (field 4, len 32, 32 'A's) is NOT text
    assert rules._text_sentinel(b"\x22\x20" + b"A" * 32) is None
    assert rules._text_sentinel(b"\x08\x96\x01") is None       # binary protobuf
    assert rules._text_sentinel(b"") is None                   # empty
    assert rules._text_sentinel(b"A" * 300) is None             # too long to be a sentinel


def test_default_table_resolves_known_endpoints():
    t = default_table()
    # wloc now routes by ARPC functionId via a custom handler (no single static message)
    wloc_req = t.request_rule("https://gs-loc.apple.com/clls/wloc")
    assert wloc_req is not None and wloc_req.handler is not None and wloc_req.message is None
    # a declarative endpoint still resolves to its committed extractor message
    assert t.request_rule("https://gsp-ssl.ls.apple.com/dispatcher.arpc").message == "geo.PDPlaceRequest"
    assert t.request_rule("https://example.com/unknown") is None


def _have_protoc_and_als():
    import shutil
    from ios_decoder.paths import PROTOS_ROOT
    return shutil.which("protoc") is not None and (PROTOS_ROOT / "locationd" / "als.proto").is_file()


@pytest.mark.skipif(not _have_protoc_and_als(), reason="protoc or committed als.proto absent")
def test_wloc_routes_by_function_id(tmp_path):
    """/clls/wloc multiplexes ALS messages by functionId: fid 1 -> ALSLocationRequest,
    fid 3 -> ALSNearbyRequest (meta is field 33 vs 35). Each must decode against its own
    schema with no cross-type 'unknown field' noise; the response routes on responseType."""
    from ios_decoder.schemas import SchemaRegistry
    from ios_decoder.paths import DEFAULT_PROTO_DIRS
    from ios_decoder.endpoints import decode_wloc_request, decode_wloc_response
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=str(tmp_path))
    ctx = DecodeContext(schemas=reg)

    # fid 3 -> ALSNearbyRequest: latitude/longitude/meta all named, nothing unknown
    Near = reg.message_class("als.proto", "als.ALSNearbyRequest")
    nm = Near(); nm.latitude = 5331082240; nm.longitude = -629944043
    nm.meta.productId = "iPhone10,1"
    out3 = decode_wloc_request(
        build_request(app="com.apple.locationd", function_id=3, payload=nm.SerializeToString()), ctx)
    assert "latitude: 5331082240" in out3 and 'productId: "iPhone10,1"' in out3
    assert "not in schema" not in out3

    # fid 1 -> ALSLocationRequest (different message on the same URL)
    Loc = reg.message_class("als.proto", "als.ALSLocationRequest")
    lm = Loc(); lm.numberOfSurroundingCells = 2
    out1 = decode_wloc_request(
        build_request(app="com.apple.locationd", function_id=1, payload=lm.SerializeToString()), ctx)
    assert "numberOfSurroundingCells: 2" in out1 and "not in schema" not in out1

    # response routes on responseType: type 3 -> ALSNearbyResponse
    NearResp = reg.message_class("als.proto", "als.ALSNearbyResponse")
    rm = NearResp(); ap = rm.wirelessAPs.add(); ap.macID = "aa:bb:cc:dd:ee:ff"
    outr = decode_wloc_response(build_response(response_type=3, payload=rm.SerializeToString()), ctx)
    assert "wirelessAPs" in outr and "aa:bb:cc:dd:ee:ff" in outr

    # an unmapped functionId must not crash — it falls back to a generic raw decode
    out_unknown = decode_wloc_request(build_request(function_id=99, payload=PROTOBUF_150), ctx)
    assert "1: 150" in out_unknown


# --- the "locus" (BluePOI) dispatcher: Wi-Fi-fingerprint lookups --------------------------

LOCUS_URL = "https://gsp57-ssl-locus.ls.apple.com/dispatcher.arpc"


def test_locus_dispatcher_resolves_to_place_request_response():
    # geod's manifest field bluePOIDispatcherURL points at gsp<N>-ssl-locus; it carries the same
    # PDPlaceRequest/PDPlaceResponse as the other dispatchers (requestType picks the payload)
    t = default_table()
    for url in (LOCUS_URL, "https://gsp12-ssl-locus.ls.apple.com/dispatcher.arpc"):
        assert t.request_rule(url).message == "geo.PDPlaceRequest"
        assert t.request_rule(url).framing == "arpc_request"
        assert t.response_rule(url).message == "geo.PDPlaceResponse"
        assert t.response_rule(url).framing == "arpc_response"
    # a different path on the host is not claimed
    assert t.request_rule("https://gsp57-ssl-locus.ls.apple.com/other") is None


def test_background_dispatcher_resolves_to_place_request_response():
    t = default_table()
    url = "https://gsp57-ssl-background.ls.apple.com/dispatcher.arpc"
    assert t.request_rule(url).message == "geo.PDPlaceRequest"
    assert t.response_rule(url).message == "geo.PDPlaceResponse"
    assert t.request_rule("https://gsp57-ssl-background.ls.apple.com/other") is None


def _have_protoc_and_geo():
    import shutil
    from ios_decoder.paths import PROTOS_ROOT
    return shutil.which("protoc") is not None and (PROTOS_ROOT / "GeoServices" / "geo.proto").is_file()


@pytest.mark.skipif(not _have_protoc_and_geo(), reason="protoc or committed geo.proto absent")
def test_locus_wifi_fingerprint_request_decodes_by_name(tmp_path):
    """A synthetic Wi-Fi-fingerprint lookup (PDPlaceRequest, requestType 32, parameters field 32)
    decodes with the locus rule into named fields and nothing falls back to by-number output."""
    from ios_decoder.decode import decode_request_body, decode_response_body
    from ios_decoder.paths import DEFAULT_PROTO_DIRS
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=str(tmp_path))
    ctx = DecodeContext(schemas=reg)
    Req = reg.message_class("geo.proto", "geo.PDPlaceRequest")

    req = Req()
    req.analyticMetadata.appIdentifier = "com.apple.test.helper"
    req.analyticMetadata.hardwareModel = "iPhone0,0"
    req.clientMetadata.deviceCountryCode = "ZZ"
    req.requestType = 32                              # REQUEST_TYPE_WIFI_FINGERPRINT_LOOKUP
    fp = req.placeRequestParameters.wifiFingerprintParameters
    fp.maxLabels = 50
    m = fp.measurements.add()
    m.entryTime, m.exitTime = 1000, 2000
    for i in range(2):                                # synthetic coordinates, not a real place
        loc = m.locations.add()
        loc.latLng.lat, loc.latLng.lng = 10.0 + i, 20.0
        loc.timestamp = 802156067.5 + i
        loc.horizontalAccuracy = 30.0
    ap = m.wifiAccessPoints.add()
    ap.macId, ap.rssi, ap.channel, ap.scanTimestamp, ap.age = "00:00:00:00:00:00", -60, 36, 802156060, 2

    out = decode_request_body(LOCUS_URL, build_request(app="com.apple.geod", function_id=60,
                                                       payload=req.SerializeToString()),
                              default_table(), ctx)
    for named in ("wifiFingerprintParameters", "measurements", "locations", "latLng",
                  "lat: 10", "horizontalAccuracy: 30", "timestamp: 802156067.5",
                  "wifiAccessPoints", 'macId: "00:00:00:00:00:00"', "rssi: -60",
                  "scanTimestamp: 802156060", "maxLabels: 50",
                  "requestType: REQUEST_TYPE_WIFI_FINGERPRINT_LOOKUP"):
        assert named in out, named
    assert "// note:" not in out and "not in schema" not in out

    # the 19-byte "no result" reply seen from the server: status 20, requestType 32, locale only
    reply = bytes.fromhex("081410202a05656e2d4945320249454a020800")
    resp = decode_response_body(LOCUS_URL, build_response(response_type=60, payload=reply),
                                default_table(), ctx)
    assert "PD_PLACE_RESPONSE_STATUS_FAILED_NO_RESULT" in resp
    assert "REQUEST_TYPE_WIFI_FINGERPRINT_LOOKUP" in resp and 'displayRegion: "IE"' in resp
    assert "// note:" not in resp


# --- photoanalysisd: direct reverse geocode and POI lookups -------------------------------

REVGEO_PR_URL = "https://gsp36-ssl.ls.apple.com/revgeo_pr.arpc"
POI_DATA_URL = "https://gsp51-ssl.ls.apple.com/api/v1.0/poi/data"


def test_photoanalysisd_endpoints_resolve():
    t = default_table()
    for url in (REVGEO_PR_URL, "https://gsp12-ssl.ls.apple.com/revgeo_pr.arpc"):
        assert t.request_rule(url).message == "geo.PDPlaceRequest"
        assert t.request_rule(url).framing == "arpc_request"
        assert t.response_rule(url).message == "geo.PDPlaceResponse"
        assert t.response_rule(url).framing == "arpc_response"
    # poi/data is the spatial lookup (manifest spatial_lookup_url), not a PDPlaceRequest
    assert t.request_rule(POI_DATA_URL).message == "geo.SpatialLookupBatchRequest"
    assert t.request_rule(POI_DATA_URL).framing == "arpc_request"
    assert t.response_rule(POI_DATA_URL).message == "geo.SpatialLookupBatchResponse"
    assert t.response_rule(POI_DATA_URL).framing == "arpc_response"
    # other paths on these hosts are not claimed
    assert t.request_rule("https://gsp36-ssl.ls.apple.com/other.arpc") is None
    assert t.request_rule("https://gsp51-ssl.ls.apple.com/api/v1.0/other") is None


@pytest.mark.skipif(not _have_protoc_and_geo(), reason="protoc or committed geo.proto absent")
def test_batch_reverse_geocode_request_decodes_by_name(tmp_path):
    """A synthetic photoanalysisd request (PDPlaceRequest, BATCH_REVERSE_GEOCODING, one asset
    location) and a spatial lookup (SpatialLookupBatchRequest) decode by name."""
    from ios_decoder.decode import decode_request_body, decode_response_body
    from ios_decoder.paths import DEFAULT_PROTO_DIRS
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=str(tmp_path))
    ctx = DecodeContext(schemas=reg)
    Req = reg.message_class("geo.proto", "geo.PDPlaceRequest")

    req = Req()
    req.analyticMetadata.appIdentifier = "com.apple.photoanalysisd"
    req.requestType = 26                              # REQUEST_TYPE_BATCH_REVERSE_GEOCODING
    p = req.placeRequestParameters.batchReverseGeocodingParameters
    loc = p.assetLocations.add()
    loc.latLng.lat, loc.latLng.lng = 10.0, 20.0       # synthetic coordinates, not a real place
    p.additionalPlaceTypes.extend([1, 2])

    out = decode_request_body(REVGEO_PR_URL, build_request(app="com.apple.photoanalysisd",
                                                           function_id=60,
                                                           payload=req.SerializeToString()),
                              default_table(), ctx)
    for named in ('appIdentifier: "com.apple.photoanalysisd"', "batchReverseGeocodingParameters",
                  "assetLocations", "lat: 10", "lng: 20", "additionalPlaceTypes: 1",
                  "requestType: REQUEST_TYPE_BATCH_REVERSE_GEOCODING"):
        assert named in out, named
    assert "// note:" not in out and "WARNING" not in out

    SReq = reg.message_class("geo.proto", "geo.SpatialLookupBatchRequest")
    sreq = SReq()
    sreq.deviceCountryCode = "ZZ"
    r = sreq.requests.add()
    r.center.lat, r.center.lng = 10.0, 20.0           # synthetic coordinates, not a real place
    r.radius = 1000
    r.categorys.extend([10, 14])                      # SPATIAL_LOOKUP_CATEGORY_RESTAURANT, _SHOPPING
    out = decode_request_body(POI_DATA_URL, build_request(app="com.apple.photoanalysisd",
                                                          function_id=1021,
                                                          payload=sreq.SerializeToString()),
                              default_table(), ctx)
    for named in ("requests", "center", "lat: 10", "lng: 20", "radius: 1000",
                  "categorys: SPATIAL_LOOKUP_CATEGORY_RESTAURANT",
                  "categorys: SPATIAL_LOOKUP_CATEGORY_SHOPPING", 'deviceCountryCode: "ZZ"'):
        assert named in out, named
    assert "// note:" not in out and "WARNING" not in out

    SResp = reg.message_class("geo.proto", "geo.SpatialLookupBatchResponse")
    resp = SResp()
    resp.responses.add().places.add().muid = 12345
    out = decode_response_body(POI_DATA_URL, build_response(response_type=1021,
                                                            payload=resp.SerializeToString()),
                               default_table(), ctx)
    assert "responses" in out and "places" in out and "muid: 12345" in out
    assert "// note:" not in out and "WARNING" not in out


# --- geod's log-message uploads (hvr/v3/use telemetry, hvr/v2/rtloc traffic probe) ----------

USE_URL = "https://gsp64-ssl.ls.apple.com/hvr/v3/use"
RTLOC_URL = "https://gsp9-ssl.apple.com/hvr/v2/rtloc"


def test_log_upload_endpoints_resolve_to_log_message_collection():
    # ARPC functionId 1017 is GEOLogMessageCollectionRequest.requestTypeCode (0x3f9) and both
    # endpoints carry it; the traffic-probe `locationCollection` bytes hold a clp message
    t = default_table()
    for url in (USE_URL, "https://gsp12-ssl.ls.apple.com/hvr/v3/use", RTLOC_URL):
        rq, rs = t.request_rule(url), t.response_rule(url)
        assert rq.message == "geo.LogMessageCollectionRequest" and rq.framing == "arpc_request"
        assert rs.message == "geo.LogMessageCollectionResponse" and rs.framing == "arpc_response"
        assert rq.embedded["geo.LogMsgEventRealtimeTrafficProbe.locationCollection"] == (
            "clp.proto", "clp.LocationCollectionRequest")
        assert rq.embedded["geo.LogMsgEventBatchTrafficProbe.locationCollection"][1] == (
            "clp.LocationCollectionRequest")
    assert t.request_rule("https://gsp9-ssl.apple.com/hvr/v2/other") is None


def test_rule_passes_embedded_map_to_registry_only_when_set():
    seen = {}

    class Spy(StubSchemas):
        def decode_with_coverage(self, proto_file, message, data, embedded=None):
            seen["embedded"] = embedded
            return super().decode_with_coverage(proto_file, message, data)

    body = build_request(payload=PROTOBUF_150)
    Rule("x.proto", "M", "arpc_request", embedded={"a.B.c": ("y.proto", "Y")}).decode(
        body, DecodeContext(schemas=Spy()))
    assert seen["embedded"] == {"a.B.c": ("y.proto", "Y")}


def _have_protoc_geo_clp():
    import shutil
    from ios_decoder.paths import PROTOS_ROOT
    return (shutil.which("protoc") is not None
            and (PROTOS_ROOT / "GeoServices" / "geo.proto").is_file()
            and (PROTOS_ROOT / "CoreLocationProtobuf" / "clp.proto").is_file())


@pytest.mark.skipif(not _have_protoc_geo_clp(), reason="protoc or committed geo/clp.proto absent")
def test_rtloc_decodes_log_message_with_embedded_location_collection(tmp_path):
    """A synthetic traffic-probe upload decodes with names all the way down: the GeoServices
    log-message wrapper and, inside `locationCollection`, the CoreLocationProtobuf message."""
    from ios_decoder.decode import decode_request_body, decode_response_body
    from ios_decoder.paths import DEFAULT_PROTO_DIRS
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=str(tmp_path))
    ctx = DecodeContext(schemas=reg)
    Log = reg.message_class("geo.proto", "geo.LogMessageCollectionRequest")
    Clp = reg.message_class("clp.proto", "clp.LocationCollectionRequest")

    inner = Clp()
    inner.meta.productId = "TEST"
    loc = inner.locations.add()
    loc.latitude, loc.longitude, loc.horizontalAccuracy = 10.5, 20.5, 5.0   # synthetic place
    inner.tripId = "AAAAAAAA-0000-0000-0000-000000000000"
    inner.appBundleIds.append("com.example.app")

    req = Log()
    msg = req.logMessages.add()
    ev = msg.logMsgEvents.add()
    ev.realtimeTrafficProbeCollection.locationCollection = inner.SerializeToString()
    out = decode_request_body(RTLOC_URL, build_request(app="com.apple.geod", function_id=1017,
                                                       payload=req.SerializeToString()),
                              default_table(), ctx)
    for named in ("logMessages", "logMsgEvents", "realtimeTrafficProbeCollection",
                  "locationCollection {", 'productId: "TEST"', "latitude: 10.5",
                  "horizontalAccuracy: 5", 'tripId: "AAAAAAAA-', 'appBundleIds: "com.example.app"'):
        assert named in out, named
    assert "// note:" not in out and "\\" not in out.split("locationCollection")[1][:80]

    # an empty acknowledgement
    ack = decode_response_body(RTLOC_URL, build_response(response_type=1017, payload=b""),
                               default_table(), ctx)
    assert "(empty payload)" in ack


@pytest.mark.skipif(not _have_protoc_geo_clp(), reason="protoc or committed geo/clp.proto absent")
def test_embedded_bytes_that_are_not_the_named_message_stay_bytes(tmp_path):
    from ios_decoder.decode import decode_request_body
    from ios_decoder.paths import DEFAULT_PROTO_DIRS
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=str(tmp_path))
    Log = reg.message_class("geo.proto", "geo.LogMessageCollectionRequest")
    req = Log()
    ev = req.logMessages.add().logMsgEvents.add()
    ev.realtimeTrafficProbeCollection.locationCollection = b"\xff\xff\xff"   # not protobuf
    out = decode_request_body(USE_URL, build_request(app="com.apple.geod", function_id=1017,
                                                     payload=req.SerializeToString()),
                              default_table(), DecodeContext(schemas=reg))
    assert 'locationCollection: "\\377\\377\\377"' in out
    assert "locationCollection {" not in out


# --- locationd's harvest uploads (/pds/pd, /hvr/trc, /psr): CoreLocationProtobuf messages ---

PDS_URL = "https://gsp10-ssl.apple.com/pds/pd"
TRC_URL = "https://gsp10-ssl.apple.com/hvr/trc"
PSR_URL = "https://gsp10-ssl.apple.com/psr"


def test_harvest_upload_endpoints_resolve_to_clp_collection_requests():
    # the ARPC requestType on the wire equals the class's requestTypeCode (Location 101,
    # Trace 109); /psr carries requestType 0 but a PressureCollectionRequest body
    t = default_table()
    for url, message in ((PDS_URL, "clp.LocationCollectionRequest"),
                         (TRC_URL, "clp.TraceCollectionRequest"),
                         (PSR_URL, "clp.PressureCollectionRequest")):
        r = t.request_rule(url)
        assert r.schema_file == "clp.proto" and r.message == message
        assert r.framing == "arpc_request"
        assert t.response_rule(url) is not None            # empty acknowledgement, header shown
    assert t.request_rule("https://gsp10-ssl.apple.com/hcy/pbcwloc").message == (
        "clp.CellWifiCollectionRequest")


@pytest.mark.skipif(not _have_protoc_geo_clp(), reason="protoc or committed geo/clp.proto absent")
def test_harvest_uploads_decode_by_name(tmp_path):
    """Synthetic /pds/pd, /hvr/trc and /psr bodies decode with CoreLocationProtobuf names and
    without the partial-schema note."""
    from ios_decoder.decode import decode_request_body
    from ios_decoder.paths import DEFAULT_PROTO_DIRS
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=str(tmp_path))
    ctx = DecodeContext(schemas=reg)
    table = default_table()

    Loc = reg.message_class("clp.proto", "clp.LocationCollectionRequest")
    pds = Loc()
    pds.meta.productId = "TEST"
    fix = pds.locations.add()
    fix.latitude, fix.longitude, fix.horizontalAccuracy, fix.speed = 10.5, 20.5, 5.0, 4.0
    pds.tripId = "BBBBBBBB-0000-0000-0000-000000000000"
    pds.appBundleIds.append("com.example.app")
    out = decode_request_body(PDS_URL, build_request(app="com.apple.locationd", function_id=101,
                                                     payload=pds.SerializeToString()), table, ctx)
    for named in ('productId: "TEST"', "locations {", "latitude: 10.5", "speed: 4",
                  'tripId: "BBBBBBBB-', 'appBundleIds: "com.example.app"'):
        assert named in out, named
    assert "// note:" not in out

    Trace = reg.message_class("clp.proto", "clp.TraceCollectionRequest")
    trc = Trace()
    trc.type = 2                                           # SCORED_COLLECTION
    ev = trc.events.add()
    ev.pressure.timestamp, ev.pressure.pressure, ev.pressure.temperature = 1.0, 99000.0, 20.5
    out = decode_request_body(TRC_URL, build_request(app="com.apple.locationd", function_id=109,
                                                     payload=trc.SerializeToString()), table, ctx)
    for named in ("TRACE_COLLECTION_REQUEST_TYPE_SCORED_COLLECTION", "events {", "pressure {",
                  "temperature: 20.5"):
        assert named in out, named
    assert "// note:" not in out

    Press = reg.message_class("clp.proto", "clp.PressureCollectionRequest")
    psr = Press()
    psr.pressure.value, psr.pressure.std = 99.1, 0.001
    psr.pressureLocation.latitude, psr.pressureLocation.longitude = 10.5, 20.5
    out = decode_request_body(PSR_URL, build_request(app="com.apple.locationd", function_id=0,
                                                     payload=psr.SerializeToString()), table, ctx)
    for named in ("pressure {", "value: 99.1", "pressureLocation {", "latitude: 10.5"):
        assert named in out, named
    assert "// note:" not in out


def test_harvest_responses_and_geod_resource_protobufs_resolve():
    t = default_table()
    for url, message in ((PDS_URL, "clp.LocationCollectionResponse"),
                         (TRC_URL, "clp.TraceCollectionResponse"),
                         (PSR_URL, "clp.PressureCollectionResponse"),
                         ("https://gsp10-ssl.apple.com/hcy/pbcwloc", "clp.CellWifiCollectionResponse")):
        r = t.response_rule(url)
        assert r.schema_file == "clp.proto" and r.message == message and r.framing == "arpc_response"
    res = "https://gspe21-ssl.ls.apple.com/other/regional_vehicle_info-7.pb?accessKey=x"
    assert t.response_rule(res).message == "geo.LPRWorld"
    assert t.response_rule(res).framing == "plain"
    att = "https://gspe21-ssl.ls.apple.com/config/search-attribution-1522?accessKey=x"
    assert t.response_rule(att).message == "geo.SearchAttributionManifest"
    # the publisher attribution manifests (protobuf map<> fields) decode by name, whatever the shard number
    for shard in ("94", "7"):
        pub = f"https://gspe21-ssl.ls.apple.com/other/publisher_attribution_dot_coms-{shard}.pb?accessKey=x"
        assert t.response_rule(pub).message == "geo.PublisherAttributionManifest"
        assert t.response_rule(pub).framing == "plain" and t.response_rule(pub).schema_file == "geo.proto"
        idx = f"https://gspe21-ssl.ls.apple.com/other/publisher_attribution_manifest_index-{shard}.pb"
        assert t.response_rule(idx).message == "geo.PublisherAttributionManifestIndex"
        assert t.response_rule(idx).framing == "plain"
    # ...and an unrelated file of the same directory is not claimed
    assert t.response_rule("https://gspe21-ssl.ls.apple.com/other/publisher_attribution_extra.pb") is None


@pytest.mark.skipif(not _have_protoc_geo_clp(), reason="protoc or committed geo/clp.proto absent")
def test_collection_ack_and_regional_vehicle_info_decode_by_name(tmp_path):
    from ios_decoder.decode import decode_response_body
    from ios_decoder.paths import DEFAULT_PROTO_DIRS
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=str(tmp_path))
    ctx = DecodeContext(schemas=reg)
    # the 2-byte acknowledgement seen from /pds/pd and /hcy/pbcwloc: CollectionResponse{success: true}
    out = decode_response_body(PDS_URL, build_response(response_type=101, payload=b"\x08\x01"),
                               default_table(), ctx)
    assert "success: true" in out and "1: 1" not in out
    World = reg.message_class("geo.proto", "geo.LPRWorld")
    w = World()
    region = w.regions.add()
    region.displayNames.add().locale = "en"
    out = decode_response_body("https://gspe21-ssl.ls.apple.com/other/regional_vehicle_info-7.pb",
                               w.SerializeToString(), default_table(), ctx)
    assert "regions {" in out and "displayNames {" in out and 'locale: "en"' in out
    assert "// note:" not in out


@pytest.mark.skipif(not _have_protoc_geo_clp(), reason="protoc or committed geo/clp.proto absent")
def test_publisher_attribution_maps_show_every_entry_by_name(tmp_path):
    """The two publisher_attribution_*.pb files are protobuf map<> fields: a repeated field whose
    entries are {key = 1, value = 2}.  Before the Extractor recovered map<K, V> the descriptor was a
    singular bytes field, which keeps only the LAST entry -- so these were left schema-free."""
    from ios_decoder.decode import decode_response_body
    from ios_decoder.paths import DEFAULT_PROTO_DIRS
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=str(tmp_path))
    ctx = DecodeContext(schemas=reg)
    publishers = [f"com.example{i}" for i in range(5)]

    Manifest = reg.message_class("geo.proto", "geo.PublisherAttributionManifest")
    m = Manifest()
    for i, key in enumerate(publishers):
        src = m.publisherAttributionSources[key]
        src.appAdamID = str(1000 + i)
        src.websiteURL = f"https://{key}"
        src.localizedAttributions.add().displayName = f"Name {i}"
    out = decode_response_body("https://gspe21-ssl.ls.apple.com/other/publisher_attribution_dot_coms-94.pb",
                               m.SerializeToString(), default_table(), ctx)
    assert out.count("publisherAttributionSources {") == len(publishers)
    for i, key in enumerate(publishers):
        assert f'key: "{key}"' in out and f'appAdamID: "{1000 + i}"' in out and f'displayName: "Name {i}"' in out
    assert "// note:" not in out

    Index = reg.message_class("geo.proto", "geo.PublisherAttributionManifestIndex")
    ix = Index()
    ix.publisherAttributionFiles.append("publisher_attribution_dot_coms.pb")
    for i, key in enumerate(publishers):
        ix.publisherToFileIndex[key] = i + 1
    out = decode_response_body("https://gspe21-ssl.ls.apple.com/other/publisher_attribution_manifest_index-78.pb",
                               ix.SerializeToString(), default_table(), ctx)
    assert 'publisherAttributionFiles: "publisher_attribution_dot_coms.pb"' in out
    assert out.count("publisherToFileIndex {") == len(publishers)
    for i, key in enumerate(publishers):
        assert f'key: "{key}"' in out and f"value: {i + 1}" in out
    assert "// note:" not in out
