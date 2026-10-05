# Decoding Apple iOS Binary Protobufs

An iPhone sends binary protobuf messages to Apple's servers for location services, maps, Siri, advertising and analytics. Apple publishes no schemas for them. This repository contains:

- **[`apple_protobuf_extractor`](apple_protobuf_extractor/README.md)**, which recovers `.proto` definitions (message and field names, field numbers, types and enums) from Apple's compiled binaries, in a Mach-O file or a dyld shared cache. It handles three protobuf runtimes: Apple's Objective-C `PBCodable` classes (by analysing their generated `writeTo:` and `readFrom:` code), Google's C++ `libprotobuf` (an exact decode of the descriptors the binary embeds) and `swift-protobuf` (names and numbers from each message's name map, types from Swift reflection metadata). No Apple headers or `.proto` sources are needed.
- **[`ios_decoder`](ios_decoder/README.md)**, which decodes captured iOS traffic (mitmproxy `.mitm` files) offline into readable protobuf using those schemas, and also handles Siri, DNS-over-HTTPS, certificates and the map and location tiles.
- **[120 recovered `.proto` files](#recovered-schemas)** (2,382 messages, 1,060 enums) in `ios_decoder/protos/`, which you can use directly.

The schemas are partly decoded. Names, numbers and types come from the binaries. The C++ schemas are exact. For `PBCodable` and `swift-protobuf` some numbers or types are estimates, most of them flagged in the output (see the [extractor README](apple_protobuf_extractor/README.md#what-it-recovers--and-the-honest-caveats)). What each endpoint is *for* comes from observed traffic, and is described [below](#protobufs-by-endpoint).

Related repositories:

- [android-protobuf-decoding](https://github.com/doug-leith/android-protobuf-decoding) is the Android counterpart, for Google Play Services protobufs.
- [poor-privacy-practices-of-the-apple-app-store](https://github.com/doug-leith/poor-privacy-practices-of-the-apple-app-store) has the measurement data and software for the Apple App Store study. It includes `addon_ios/ios_decoding_helpers.py`, the live mitmdump addon that `ios_decoder` was rewritten from, and the tweak used to bypass SSL certificate checks when capturing traffic.

## Quick start

Clone this repository and install into a virtual environment (Python 3.12 or later). The [`protoc`](https://github.com/protocolbuffers/protobuf/releases) compiler must be on your `PATH`, for example `brew install protobuf` on macOS.

```sh
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

To test the installation, decode the example capture:

```sh
./venv/bin/python3 -m ios_decoder.report examples/example.mitm | diff - examples/example_output.txt
```

No output from `diff` means the decoded output matches `examples/example_output.txt`. The capture holds three flows: a Wi-Fi location lookup (`gs-loc.apple.com/clls/wloc`) and a sensor-trace upload (`hvr/trc`), both built from the real schemas with made-up values, and one real telemetry upload (`hvr/v3/use`). They are shown [below](#decoded-examples). `examples/make_example_capture.py` rebuilds both files.

## What is in this repository

| Path | Contents |
|---|---|
| [`apple_protobuf_extractor/`](apple_protobuf_extractor/README.md) | The schema extractor. |
| [`ios_decoder/`](ios_decoder/README.md) | The traffic decoder. `endpoints.py` is the table that maps URLs to messages. |
| `ios_decoder/protos/` | The recovered schemas, one folder per Apple framework. |
| `examples/` | The example capture, its expected output, and the script that builds them. |
| `ios_decoder/tests/fixtures/` | Small real extracts of captured traffic, used by the tests. |
| `apple_protobuf_extractor/tests/` | Tests, with synthetic compiled fixtures and golden outputs. |

## Decoding a capture

Record the phone's traffic with [mitmproxy](https://mitmproxy.org) (`mitmdump -w capture.mitm`), then:

```sh
# Everything in a capture, decoded flows only
./venv/bin/python3 -m ios_decoder.report capture.mitm --decoded-only

# Only the traffic from geod, the daemon that makes map and place requests
./venv/bin/python3 -m ios_decoder.report capture.mitm --user-agent geod --decoded-only

# GeoServices place lookups, first 5, raw bodies in full
./venv/bin/python3 -m ios_decoder.report capture.mitm --url 'dispatcher\.arpc' --limit 5 --full-bodies

# What domains did the device resolve? (DNS-over-HTTPS)
./venv/bin/python3 -m ios_decoder.report capture.mitm --url 'dns-query' --decoded-only
```

The [`ios_decoder` README](ios_decoder/README.md) lists all the options. Decrypting the phone's HTTPS traffic needs the system processes' certificate checks to be bypassed. In our measurements the iPhone 8 was jailbroken with palera1n, a modified SSL Kill Switch tweak bypassed certificate pinning, and `mitmdump` acted as a transparent proxy. The App Store repository above includes an SSL-bypass tweak.

## Extracting schemas from Apple binaries

```sh
# Extract one framework from the dyld cache  ->  ./protos/*.proto
./venv/bin/python3 apple_protobuf_extractor/cli.py --framework GeoServices --cache iphone8_data/dylib -o ./protos/

# Extract from a standalone Mach-O binary (no cache needed)
./venv/bin/python3 apple_protobuf_extractor/cli.py --binary iphone8_data/locationd -o ./protos/

# List every framework embedded in the cache
./venv/bin/python3 apple_protobuf_extractor/cli.py --list-frameworks --cache iphone8_data/dylib
```

The same command extracts all three runtimes. A binary's messages are grouped into `.proto` files whose `// Serializer:` header names the runtime they came from:

```sh
# Which protobuf runtimes does a binary use, and which messages are in each?
./venv/bin/python3 apple_protobuf_extractor/cli.py --binary iphone8_data/libexec/remindd --list-serializers

# swift-protobuf: remindd gives remindd.proto (its own messages) and swiftprotobuf.proto (the Google well-known types it links)
./venv/bin/python3 apple_protobuf_extractor/cli.py --binary iphone8_data/libexec/remindd -o ./protos/

# C++ libprotobuf and PBCodable together: locationd gives 65 PBCodable and 334 C++ messages, every field number confirmed
./venv/bin/python3 apple_protobuf_extractor/cli.py --binary iphone8_data/locationd -o ./protos/
```

Google's Objective-C runtime (`GPBMessage`) and `libprotobuf-lite` (which strips its descriptors) are detected and reported, but not decoded.

The dyld cache and binaries are Apple's software and are not in this repository. [Getting the Apple artifacts](#getting-the-apple-artifacts-optional) below shows how to download them.

## Recovered schemas

`ios_decoder/protos/` holds the extractor's output, one folder per framework. Each file starts with a header naming the tool, the serializer (`Apple PBCodable (ObjC)` or `C++ libprotobuf (google::protobuf)`) and the source framework. In `geo.proto`, `als.proto` and `clp.proto` the Objective-C class prefix is dropped (`GEOPDPlaceRequest` is `geo.PDPlaceRequest`).

| Framework | `.proto` files | Messages | What is in it |
|---|---|---|---|
| `GeoServices` | 6 | 1,692 | Maps, places and geocoding, Wi-Fi quality and `geod` telemetry. `geo.proto` holds most of the `GEO*` messages. |
| `locationd` | 25 | 399 | Wi-Fi and cell location lookup (`als.proto`) and other `locationd` messages. |
| `CoreLocationProtobuf` | 1 | 84 | Cell and Wi-Fi observation, location, trace and pressure uploads (`clp.proto`). |
| `AppPredictionInternal` | 8 | 99 | App-prediction messages (`atx.proto`, used by the `DuetExpert` feedback channel). |
| `CoreParsec` | 77 | 77 | Feedback and usage messages, for example `_cpusageenvelope.proto` and `_cpclientsession.proto`. |
| `ProactiveEventTracker` | 2 | 8 | `pet.proto`, used by the `ProactiveEventTracker` feedback channels. |
| `AdCore` | 1 | 23 | The iAd advertising SDK: opt-out, segment update, settings, configuration, analytics and user-transparency requests and responses (`ad.proto`). |

103 of the files (1,998 messages) were recovered from `PBCodable` classes. The other 17 (384 messages) are exact decodes of C++ `libprotobuf` descriptors: five in `GeoServices` (`addressobject`, `compressed_path`, `descriptor`, `geo3_slim` and `path`) and twelve in `locationd`, mostly GNSS and log-entry types such as `gnssemergencytypes.proto` and `clpprivatedatacapture.proto`. 

## Protobufs by endpoint

The decoder recognises the endpoints below (the table is `ios_decoder/endpoints.py`). The descriptions are based on traffic from an iPhone 8 running iOS 16.7.11. Server names such as `gsp10-ssl.apple.com` vary, so `*` stands for the number.

<!-- BEGIN endpoint-table (generated by ios_decoder/endpoint_docs.py; do not edit by hand) -->

#### Location lookups and crowdsourced uploads (`locationd`)

`locationd` hosts the phone's location providers. It asks Apple where Wi-Fi access points and cell towers are, and uploads ("harvests") sensor data. The uploads below are ARPC requests with function IDs 100 (`pbcwloc`), 101 (`pds/pd`) and 109 (`hvr/trc`); `psr` is sent with function ID 0.

| Endpoint | What it is | Messages |
|---|---|---|
| `gs-loc.apple.com/clls/wloc` | Wi-Fi and cell location lookup. The handset sends a Wi-Fi MAC address or a cell-tower identity (in one request its own latitude and longitude) and gets back the positions of nearby access points or towers. | request: `als.ALSLocationRequest` (function 1) or `als.ALSNearbyRequest` (function 3)<br>response: `als.ALSLocationResponse` or `als.ALSNearbyResponse` |
| `gsp*-ssl.apple.com/hcy/pbcwloc` | Cell and Wi-Fi observation upload: cell-tower (MCC, MNC, TAC, cell ID, signal strength) and Wi-Fi (MAC address, channel, signal strength) records, each with the handset location and motion state. | request: `clp.CellWifiCollectionRequest`<br>response: `clp.CellWifiCollectionResponse` |
| `gsp*-ssl.apple.com/pds/pd` | GPS fix upload: locations with altitude, accuracy, speed, course and motion state, the bundle ID of the app using location, and a trip ID. | request: `clp.LocationCollectionRequest`<br>response: `clp.LocationCollectionResponse` |
| `gsp*-ssl.apple.com/hvr/trc` | Sensor trace upload: pressure, temperature, locations with GNSS satellite reports, compass attitude, pedometer and motion state, and the app bundle ID. | request: `clp.TraceCollectionRequest`<br>response: `clp.TraceCollectionResponse` |
| `gsp*-ssl.apple.com/psr` | Barometric pressure upload: a pressure reading and timestamp, with the GPS fix at the time of the reading. | request: `clp.PressureCollectionRequest`<br>response: `clp.PressureCollectionResponse` |

#### Telemetry, experiments and configuration (`geod`)

`geod` is the daemon that makes map and place requests on behalf of the system and apps, and reports usage back to Apple.

| Endpoint | What it is | Messages |
|---|---|---|
| `gsp*-ssl.ls.apple.com/hvr/v3/use` | Telemetry. Batched log records describing each network request `geod` makes and the client that made it, with handset model, OS version, country code, carrier and connectivity type. Daily records carry a session ID. ARPC function 1017, LZ4-compressed. | request: `geo.LogMessageCollectionRequest`<br>response: `geo.LogMessageCollectionResponse` |
| `gsp*-ssl.apple.com/hvr/v2/rtloc` | Real-time traffic probe sent by `geod`: a sequence of timestamped GPS locations with accuracy and motion type, sent within a minute of the fixes. | request: `geo.LogMessageCollectionRequest`<br>response: `geo.LogMessageCollectionResponse` |
| `gsp-ssl.ls.apple.com/ab.arpc` | A/B experiments. The handset sends a random GUID, locale, OS version and country code and gets back an experiment bucket ID for the Parsec, Siri, RAP and Maps namespaces. | request: `geo.ABAssignmentRequest`<br>response: `geo.ABAssignmentResponse` |

#### Places and geocoding

Place and address lookups. All use the `PDPlaceRequest` message on different hosts. Requests name the calling client, and some carry a precise location.

| Endpoint | What it is | Messages |
|---|---|---|
| `gsp-ssl.ls.apple.com/dispatcher.arpc` | Reverse geocoding and place data. The request names the calling client (for example the Weather widget); the reply is a street address, bounding polygons and place data. | request: `geo.PDPlaceRequest`<br>response: `geo.PDPlaceResponse` |
| `gsp*-ssl-revgeo.ls.apple.com/dispatcher.arpc` | Reverse geocoding on behalf of system clients such as CoreRoutine, `analyticsd` and `networkserviceproxy`. Carries GPS coordinates. | request: `geo.PDPlaceRequest`<br>response: `geo.PDPlaceResponse` |
| `gsp*-ssl-background.ls.apple.com/dispatcher.arpc` | Place lookup on the `-background` dispatcher host; the same `PDPlaceRequest` message. | request: `geo.PDPlaceRequest`<br>response: `geo.PDPlaceResponse` |
| `gsp*-ssl-locus.ls.apple.com/dispatcher.arpc` | Wi-Fi fingerprint lookup from CoreRoutine: timestamped locations, MAC addresses and signal strengths of nearby access points, and visit entry and exit times. The reply is a status only. | request: `geo.PDPlaceRequest`<br>response: `geo.PDPlaceResponse` |
| `gsp*-ssl.ls.apple.com/revgeo_pr.arpc` | Reverse geocoding request (`PDPlaceRequest`). | request: `geo.PDPlaceRequest`<br>response: `geo.PDPlaceResponse` |
| `gsp*-ssl.ls.apple.com/api/v1.0/poi/data` | Point-of-interest lookup (a batched spatial lookup). | request: `geo.SpatialLookupBatchRequest`<br>response: `geo.SpatialLookupBatchResponse` |

#### Wi-Fi quality

Used by the Wi-Fi pre-fetch service (`ThreeBarsXPCService`).

| Endpoint | What it is | Messages |
|---|---|---|
| `gsp*-ssl.ls.apple.com/wifi_request` | Wi-Fi quality lookup: the BSSID of the access point the handset is using, with locale and country code. Sent even when location is off. The reply is a quality status for that BSSID. | request: `geo.WiFiQualityServiceRequest`<br>response: `geo.WiFiQualityServiceResponse` |
| `gspe*-ssl.ls.apple.com/wifi_request_tile` | Wi-Fi quality tile: per-access-point records with packed BSSID, latitude and longitude, popularity score, authentication type and a public-network flag. | response: `geo.WiFiQualitySearchResultTile` |

#### Map manifests and resources

Downloaded without a location by `geod`.

| Endpoint | What it is | Messages |
|---|---|---|
| `gspe*-ssl.ls.apple.com/geo_manifest/dynamic/config` | The GeoServices manifest: the resources `geod` can fetch (map tiles, fonts, icons, textures) and the endpoint URLs of the other services. | response: `geo.Resources` |
| `gspe*-ssl.ls.apple.com/config/search-attribution-N` | Search attribution manifest (`SearchAttributionManifest`). | response: `geo.SearchAttributionManifest` |
| `gspe*-ssl.ls.apple.com/other/publisher_attribution_dot_coms-N.pb` | Publisher attribution manifest (`PublisherAttributionManifest`). | response: `geo.PublisherAttributionManifest` |
| `gspe*-ssl.ls.apple.com/other/publisher_attribution_manifest_index-N.pb` | Index of the publisher attribution manifests. | response: `geo.PublisherAttributionManifestIndex` |
| `gspe*-ssl.ls.apple.com/other/regional_vehicle_info-N.pb` | Regional vehicle (EV) information (`LPRWorld`). | response: `geo.LPRWorld` |

#### Feedback, advertising and certificates

Feedback and analytics uploads, advertising SDK traffic and certificate responses.

| Endpoint | What it is | Messages |
|---|---|---|
| `fbs.smoot.apple.com/fb and api.smoot.apple.com/fb` | Feedback and analytics upload. The message depends on the `?type=` channel. | request, by `?type=`: `FeedbackV2PB` → `_cpclientsession._CPClientSession`; `Usage` → `_cpusageenvelope._CPUsageEnvelope`; `ProactiveEventTracker` → `pet.PETUpload`; `ProactiveEventTrackerAggregated` → `pet.PETUpload`; `DuetExpert` → `atx.ATXNotificationsPBLogWrapper` |
| `xp.apple.com/report/` | XP analytics reports. The body is nested JSON; embedded base64, gzip and protobuf are expanded. The `iAdMetadata` field of ad impressions is a protobuf whose schema is not in the iOS cache, so it is decoded without one. | request: nested JSON, with embedded base64, gzip and protobuf expanded |
| `amp-api*.apps.apple.com/v1/engagement` | App Store engagement traffic: adverts, upsell and subscription offers, and analytics on user behaviour. Nested JSON, expanded the same way as XP. | request and response: nested JSON, with embedded base64, gzip and protobuf expanded |
| `iadsdk.apple.com/adserver/2.6/optout/optout_optin` | iAd opt-out / opt-in: the handset reports its ad-tracking opt-out status with its iAd ID, timestamps and time zone. | request: `ad.ADOptOutRequest`<br>response: `ad.ADOptOutResponse` |
| `iadsdk.apple.com/adserver/2.6/segment/update` | iAd segment update: the handset sends its iAd ID, advertising identifier, OS version and build, locale, device modes and account types; the reply gives the intervals before the next update. | request: `ad.ADSegmentUpdateRequest`<br>response: `ad.ADSegmentUpdateResponse` |
| `tr.iadsdk.apple.com/adserver/2.6/settings` | iAd client settings: the handset sends its iAd ID and current settings; the reply holds the search-ads and search-landing-ads settings and an expiration date. | request: `ad.ADClientSettingsRequest`<br>response: `ad.ADClientSettingsResponse` |
| `cf.iadsdk.apple.com/adserver/2.6/config` | iAd configuration: the handset sends its current configurations; the reply lists the configurations, the proxy URLs and a configuration version. | request: `ad.ADConfigurationRequest`<br>response: `ad.ADConfigurationResponse` |
| `iadsdk.apple.com/adserver/2.6/event/analytics` | iAd analytics upload: a batch of events (for example an ad-transparency screen appearing) with the iAd ID and the app's bundle ID. | request: `ad.ADLogAnalyticsRequest`<br>response: `ad.ADLogAnalyticsResponse` |
| `iadsdk.apple.com/adserver/2.6/privacy/user-transparency` | iAd user transparency: the handset sends its locale, iAd ID, store, and whether ad tracking is limited and whether it is signed in to iTunes; the reply holds the transparency details. | request: `ad.ADUserTransparencyRequest`<br>response: `ad.ADUserTransparencyResponse` |
| `iadsdk.apple.com/adserver/2.6/… (any other path)` | Any other iAd SDK 2.6 request. No schema is known for it. | request and response: 8-byte iAd header, then a protobuf decoded without a schema |
| `humb.apple.com/humbug/baa` | Certificate response. | response: X.509 certificate chain (PEM) |
| `swallow.apple.com/…GetCertificate` | Certificate response from the Siri `swallow` service. | response: X.509 certificate chain (DER) |

#### Tiles (`locationd` and `geod`)

`locationd` puts the south-west corner of the tile, in degrees, in the URL path (`1433500_1738000` means latitude 53.35, longitude -6.20), so each download tells Apple the area the handset is in. The global tiles name no location. Each is decoded by a tile parser in `ios_decoder/tile_tools`.

| Endpoint | What it is | Messages |
|---|---|---|
| `cl2.apple.com/1/v1/N` | Wi-Fi tile: Wi-Fi MAC addresses and their latitude and longitude. About 5 km across. | response: tile parser `wifi` |
| `cl2.apple.com/3/v1/N` | GSM cell tile: cell identifiers, locations and coverage footprints for one carrier network (the carrier is encoded in the URL). | response: tile parser `gsmcell` |
| `cl2.apple.com/4/v1/N` | LTE cell tile: LTE cell identifiers (TAC and global cell ID) and their locations for one carrier network. | response: tile parser `ltecell` |
| `cl3.apple.com/2/v1/N` | High-resolution signal environment (HRSE) tile: the radio signal environment class at fine resolution over the tile. | response: tile parser `hrse` |
| `cl3.apple.com/3/v2/N` | Digital elevation model tile: altitudes on a grid across the tile. | response: tile parser `cldem` |
| `cl2.apple.com/6/v1/N` | Global GSM cell tile: a list of GSM cells (MCC, MNC, cell ID) and their locations. | response: tile parser `global_gsm` |
| `cl2.apple.com/7/v1/N` | Global CDMA tile: a list of CDMA base station IDs. | response: tile parser `global_cdma` |
| `cl2.apple.com/8/v1/N` | Global LTE tile: a list of LTE global cell IDs. | response: tile parser `global_lte` |
| `cl2.apple.com/11/v1/N` | Global 5G tile: a list of 5G NR cell IDs. | response: tile parser `global_5g` |
| `cl3.apple.com/3/v2/cldavl.avl.gz` | Tile availability index: bitmaps of which geographic tiles have data on the server. | response: tile parser `cldavl` |
| `cl3.apple.com/1/v2/clsef.bin.gz` | Global coarse signal-environment map: a raster covering the Earth at 0.05 degree resolution. | response: tile parser `clsef` |

<!-- END endpoint-table -->

### How the traffic is framed

Most `geod` and `locationd` requests use Apple's ARPC framing. A request starts with a 2-byte version, then length-prefixed locale, app identifier and OS-version strings (version 2 adds the compression algorithm), a 4-byte function ID and a 4-byte payload length, followed by the protobuf. A response has a version, a response type and a payload length. Compressed payloads use Apple's `bvx` LZ4 framing (`bv41` blocks that share a dictionary, `bv4-` stored blocks and a `bv4$` end marker). The decoder prints the header on the first line of each body, as `apple arpc header: ...`.

### Decoded examples

These come from `examples/example.mitm`. The `wloc` and `hvr/trc` values are made up (the MAC addresses are in the range reserved for documentation, and the coordinates are those of Apple Park). The `hvr/v3/use` body is real.

<!-- BEGIN examples (generated by ios_decoder/endpoint_docs.py; do not edit by hand) -->

#### A Wi-Fi location lookup (`wloc`)

The handset sends one Wi-Fi MAC address; Apple returns the positions of that access point and its neighbours.

```text
POST https://gs-loc.apple.com/clls/wloc
Request body (decoded):
apple arpc header: version=1, locale=en_US, app=com.apple.locationd, osVersion=16.7.11.20H360, requestType=1, length=70
wirelessAPs {
  macID: "00:00:5e:00:53:01"
}
numberOfSurroundingWifis: 100
surroundingWifiBands: ALS_LOCATION_REQUEST_SURROUNDING_WIFI_BANDS_K2DOT4_GHZ
wifiAltitudeScale: ALS_LOCATION_REQUEST_WIFI_ALTITUDE_SCALE_K_WIFI_ALTITUDE_SCALE10TO_THE2
meta {
  softwareBuild: "iPhone OS16.7.11/20H360"
  productId: "iPhone10,1"
}
Response body (decoded):
apple header: version=1, responseType=1, payloadLength=224
wirelessAPs {
  macID: "00:00:5e:00:53:01"
  location {
    latitude: 3733490000
    longitude: -12200900000
    accuracy: 20
    locationType: 3
    altitude: 48
    verticalAccuracy: 1000
    score: 53
    reach: 89
  }
  channel: 1
}
wirelessAPs {
  macID: "00:00:5e:00:53:02"
  location {
    latitude: 3733530000
    longitude: -12200930000
    accuracy: 25
    locationType: 3
    altitude: 48
    verticalAccuracy: 1000
    score: 53
    reach: 89
  }
  channel: 6
}
...
```

#### A sensor-trace upload (`hvr/trc`)

`locationd` uploads GPS fixes and a pressure reading.

```text
POST https://gsp10-ssl.apple.com/hvr/trc
Request body (decoded):
apple arpc header: version=1, locale=en_US, app=com.apple.locationd, osVersion=16.7.11.20H360, requestType=109, length=241
meta {
  productId: "D20AP"
  softwareVersion: "iPhone OS16.7.11/20H360"
}
events {
  type: INDOOR_EVENT_TYPE_LOCATION
  location {
    latitude: 37.3349
    longitude: -122.009
    horizontalAccuracy: 5
    altitude: 61.5
    verticalAccuracy: 4
    speed: 1.5
    course: 110
    timestamp: 802283024
    provider: 1
  }
}
events {
  type: INDOOR_EVENT_TYPE_LOCATION
  location {
    latitude: 37.335
    longitude: -122.0091
    horizontalAccuracy: 5
    altitude: 61.5
    verticalAccuracy: 4
    speed: 1.5
    course: 110
    timestamp: 802283025
    provider: 1
  }
}
...
```

#### A telemetry upload (`hvr/v3/use`)

`geod` reports a network request it made (here a failed Wi-Fi quality lookup) with the handset model, OS version and a session ID.

```text
POST https://gsp64-ssl.ls.apple.com/hvr/v3/use
Request body (decoded):
apple arpc header: version=2, locale=en-IE_IE, app=com.apple.geod, osVersion=16.7.11.20H360, compressionAlgo=LZ4, requestType=1017, length=323
logMessages {
  logMsgEvents {
    logMsgStates {
      stateType: LOG_MSG_STATE_TYPE_APPLICATION_IDENTIFIER
      applicationIdentifier {
        appIdentifier: "com.apple.geod"
      }
    }
    logMsgStates {
      stateType: LOG_MSG_STATE_TYPE_CAR_PLAY
      carPlay {
      }
    }
    logMsgStates {
      stateType: LOG_MSG_STATE_TYPE_DEVICE_SETTINGS
      deviceSettings {
      }
    }
    logMsgStates {
      stateType: LOG_MSG_STATE_TYPE_DEVICE_CONNECTION
      deviceConnection {
        deviceNetworkConnectivity: DEVICE_NETWORK_CONNECTIVITY_WIFI
        deviceCountryCode: "IE"
        deviceCarrierName: "48"
        cellularDataState: CELLULAR_DATA_STATE_ALLOWED
      }
    }
    logMsgStates {
      stateType: LOG_MSG_STATE_TYPE_DEVICE_IDENTIFIER
      deviceIdentifier {
        deviceOsVersion: "16.7.11.20H360"
        deviceHwIdentifier: "iPhone10,1"
      }
    }
    logMsgStates {
      stateType: LOG_MSG_STATE_TYPE_EXPERIMENTS
      experiments {
        datasetAbStatus {
        }
      }
    }
    logMsgStates {
      stateType: LOG_MSG_STATE_TYPE_MUNIN_RESOURCE_LOG
      muninResource {
      }
    }
    logMsgStates {
      stateType: LOG_MSG_STATE_TYPE_USER_SESSION
      userSession {
        sessionId: "\010\277\315\231\237\254\301\215\201p\020\370\377\301\333\203\265\374%"
        relativeTimestamp: 793048500
        eventTime {
          timeRoundedToHour: 793047600
        }
        ageOfSessionIdInSeconds: 450835
      }
    }
    eventType: LOG_MSG_EVENT_TYPE_NETWORK
    networkEvent {
      networkService: LOG_MSG_EVENT_NETWORK_SERVICE_WIFI_QUALITY
      requestDataSize: 119
      responseDataSize: 64
      requestAppIdentifier: "com.apple.wifi.ThreeBarsXPCService"
      totalTime: 2073
      httpResponseCode: 200
      manifestEnv: "prod"
      tilesetId: 2602162
      serviceIpAddress: "17.167.200.74:443"
      requestAppIdMinorVer: "1"
      samplingRate: 10000
      taskMetrics {
      }
    }
  }
  logMessageType: LOG_MESSAGE_TYPE_LONG_SESSION_USAGE
}
Response body (decoded):
apple header: version=1, responseType=1017, payloadLength=0
(empty payload)
```

<!-- END examples -->

## Tests

```sh
./venv/bin/python3 -m pytest
```

Without Apple artifacts or captures, a large part of the suite skips by design (227 tests in
a clean checkout, all in the extractor suite; `ios_decoder` needs no Apple data). The summary says so, and a green run in that state does **not**
mean the extractor was exercised against real binaries.

- **Live extractor tests** need the Apple artifacts: a dyld shared cache and the `locationd`
  binary. Put them in `./iphone8_data/`, or point `MACHO_DATA_DIR` at a directory
  that holds them. Set `MACHO_REQUIRE_LIVE=1` to make a missing artifact a failure instead of a skip.
  The 8 iOS 27 tests (`test_newer_toolchain_ios27.py`) look for `./ios27_data/dylib/dyld_shared_cache_arm64e`,
  or for the directory named by `MACHO_TEST_IOS27_CACHE`.
- **Real tile, Siri, ARPC and `/fb` tests** use extracts of real captured traffic that are committed
  under `ios_decoder/tests/fixtures/` (about 2.8 MB). They can be
  regenerated from your own `.mitm` captures with `extract_tile_samples.py`, `extract_tcp_samples.py`
  and `extract_request_samples.py` (all in `ios_decoder/tests/`); no capture is needed to run the tests.

## Getting the Apple artifacts (optional)

The live tests analyse Apple's own dyld shared caches and binaries. That software is Apple's, so
this repository does not include it, and those tests skip when it is absent. To run them you can
fetch your own copy from Apple's public firmware with [`ipsw`](https://github.com/blacktop/ipsw)
(use is subject to Apple's licence terms). Everything below is written into `iphone8_data/` and
`ios27_data/`.  Run the commands
from the repository root, in a `bash` or `zsh` shell.

**Which firmware.** The golden outputs were generated from an iPhone 8 on **iOS 16.7.11, build
20H360**. `iPhone10,1` and `iPhone10,4` share that firmware. A different build will not match the
golden files.

**1. Install `ipsw`.** The commands here were written for ipsw 3.1.x.

```sh
brew install blacktop/tap/ipsw        # macOS; Homebrew may ask you to run: brew trust blacktop/tap
sudo snap install ipsw                # Linux
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket.git && scoop install blacktop/ipsw   # Windows
```

Release binaries are also on the [ipsw releases page](https://github.com/blacktop/ipsw/releases/latest).

**2. Download the iPhone 8 firmware (about 6 GB).** `--urls` instead prints Apple's download URL without
downloading anything.

```sh
mkdir -p iphone8_data/ipsw iphone8_data/dylib
ipsw download ipsw --device iPhone10,1 --build 20H360 --output iphone8_data/ipsw --confirm
IPSW=$(find iphone8_data/ipsw -name '*20H360*.ipsw' | head -1); echo "$IPSW"
```

**3. Extract the dyld shared cache.** This writes `dyld_shared_cache_arm64` and its numbered
sub-caches. If `ipsw` puts them in a sub-folder, the second command moves them up to where the tests look.

```sh
ipsw extract --dyld --dyld-arch arm64 --output iphone8_data/dylib "$IPSW"
find iphone8_data/dylib -mindepth 2 -name 'dyld_shared_cache_arm64*' -exec mv {} iphone8_data/dylib/ \;
```

Check that you have the right cache:

```sh
ipsw dyld info iphone8_data/dylib/dyld_shared_cache_arm64 | grep -E 'OS Version|Num Images|Cache UUID'
# expect:  OS Version = 16.7,  Num Images = 2705,  Cache UUID: F203FF1D-3CE6-3F7A-9849-791B1C1F4B8B
```

**4. Extract the standalone binaries** (`locationd`, `geod`, `remindd`, `transparencyd`,
`nptocompaniond`, `DPSubmissionService`) and put them where the tests expect them.

```sh
ipsw extract --files --output iphone8_data/extracted \
  --pattern '(usr/libexec/(locationd|remindd|transparencyd|nptocompaniond)|GeoServices\.framework/geod|DPSubmissionService\.xpc/DPSubmissionService)$' \
  "$IPSW"
mkdir -p iphone8_data/libexec
find iphone8_data/extracted -type f \( -name remindd -o -name transparencyd -o -name nptocompaniond \) -exec mv {} iphone8_data/libexec/ \;
find iphone8_data/extracted -type f \( -name locationd -o -name geod -o -name DPSubmissionService \) -exec mv {} iphone8_data/ \;
```

`ipsw` recreates the firmware's folder layout under `iphone8_data/extracted/`, so the two `find` commands
do the moving.

**5. Extract the GeoServices image from the cache.** This prints an "experimental" warning; that is expected.

```sh
ipsw dyld extract iphone8_data/dylib/dyld_shared_cache_arm64 GeoServices --output iphone8_data
```

**6. iOS 27 cache (optional; about 12 GB).** Only the 8 tests in `test_newer_toolchain_ios27.py`
use it. This extracts just the cache from Apple's server, without keeping the whole firmware.

```sh
mkdir -p ios27_data/dylib
ipsw download ipsw --device iPhone17,3 --build 24A437 --dyld --dyld-arch arm64e --output ios27_data/dylib --confirm
find ios27_data/dylib -mindepth 2 -name 'dyld_shared_cache_arm64e*' -exec mv {} ios27_data/dylib/ \;
```

**7. Run the suite with the live tests enforced.**

```sh
MACHO_REQUIRE_LIVE=1 ./venv/bin/python3 -m pytest
```

With everything in place, nothing should skip (without step 6, the 8 iOS 27 tests skip). The firmware downloaded in step 2
can be deleted afterwards (`rm -r iphone8_data/ipsw`); the tests do not use it.

## Provenance

This repository was created as a snapshot of two directories from a larger private research
repository, taken at its commit `9115ef2`. It starts with no history. Some things you will meet in
the code reflect that origin including comments and notes refer to predecessor tools that are not included and to commit hashes from the original repository.

