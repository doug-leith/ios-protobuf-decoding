"""Hand-verified swift-protobuf ground truth (regression baseline).

Ground truth is derived INDEPENDENTLY of the tool's primary path and certified
against raw disassembly — see notes/SWIFT_PROTO_HAND_VERIFICATION.md Part 3 for
the per-field derivation (nameMap closure for number+name, __swift5_fieldmd for
type, traverse/decodeMessage cross-checks, raw-disasm spot certification).

Each ground-truth entry is ``number -> (name, expected_recovered_type)`` where
``expected_recovered_type`` is what the tool SHOULD currently emit
(``f.proto_type``):
  * for fields the tool fully recovers, this is the TRUE proto type;
  * for KNOWN-DEGRADED fields it is the current degraded output, with the TRUE
    value + the tracking to-do in a comment — so the test guards against
    regression now and FAILS (prompting an update) when the gap is fixed.

Cache tests need the dyld cache + its .symbols sub-cache; the remindd test needs
the standalone binary. All gated on availability.
"""
import os
import unittest

from serializers import swift_descriptor_extract as SW


def _cache_path():
    try:
        import artifacts
        p = artifacts.cache_file()
        return p if p and os.path.isfile(p) and os.path.isfile(p + ".symbols") else None
    except Exception:
        return None


def _remindd_path():
    p = os.environ.get("MACHO_TEST_REMINDD", "").strip()
    if p:
        return p if os.path.isfile(p) else None
    try:
        import artifacts
        p = os.path.join(artifacts.data_dir(), "libexec", "remindd")
        return p if os.path.isfile(p) else None
    except Exception:
        return None


def _by_number(msgs):
    """{message_name: {number: (name, proto_type)}} from a swift_messages list."""
    out = {}
    for m in msgs:
        out[m.name] = {f.number: (f.name, f.proto_type) for f in m.fields}
    return out


# ── certified ground truth — expected CURRENT tool output (degraded marked) ──────

SIRI = {
    "ProtoDateComponentSignal": {1: ("year", "uint32"), 2: ("month", "uint32"),
        3: ("day", "uint32"), 4: ("hour", "uint32"), 5: ("minute", "uint32"),
        6: ("second", "uint32")},
    "ProtoMediaEntitySignal": {1: ("adamIdentifier", "string"),
        2: ("artist", "string"), 3: ("title", "string"), 4: ("album", "string")},
    "ProtoDateTimeEntitySignal": {1: ("datetimeTimestampMs", "uint64")},
    "ProtoPlayMediaTaskFeatureSet": {1: ("playDurationInSec", "double"),
        2: ("mediaContentLengthInSec", "double"), 3: ("appBundleId", "string"),
        4: ("actionState", "string"), 5: ("mediaEntity", "ProtoMediaEntitySignal")},
    "ProtoReminderTaskFeatureSet": {1: ("reminderIdentifier", "string"),
        2: ("isSpatialTriggered", "bool"), 3: ("isTemporalTriggered", "bool"),
        4: ("startTime", "ProtoDateTimeEntitySignal"),
        5: ("endTime", "ProtoDateTimeEntitySignal")},
    "ProtoSiriTaskInteractionType": {1: ("includesPrompt", "bool"),
        2: ("includesConfirm", "bool"), 3: ("includesDisambiguate", "bool"),
        4: ("includesUnsupportedPrompt", "bool")},
    "ProtoSiriTaskEvaluationSummary": {
        1: ("requestIds", "repeated string"),         # [String] (Remote Mirror; #124)
        2: ("taskCompletion", "ProtoSiriTaskCompletionType"),
        3: ("taskSuccess", "ProtoSiriTaskSuccessType"),
        4: ("interactionType", "ProtoSiriTaskInteractionType"),
        5: ("startTimestampMs", "uint64"), 6: ("endTimestampMs", "uint64")},
    "ProtoTaskFeatureSet": {                          # oneof + high numbers (#60 resolved)
        1: ("appBundleId", "string"),
        101: ("startCallFeatureSet", "ProtoStartCallTaskFeatureSet"),
        102: ("sendMessageFeatureSet", "ProtoSendMessageTaskFeatureSet"),
        103: ("alarmFeatureSet", "ProtoAlarmTaskFeatureSet"),
        104: ("reminderFeatureSet", "ProtoReminderTaskFeatureSet"),
        105: ("playMediaFeatureSet", "ProtoPlayMediaTaskFeatureSet")},
}

MESSAGE_PROTECTION = {
    "MPPB_KeyAndIndex": {1: ("key", "bytes"), 2: ("index", "uint64")},
    "MPPB_RatchetState": {1: ("chainKey", "MPPB_KeyAndIndex"),
        2: ("messageKeys", "repeated MPPB_KeyAndIndex")},  # #69: symref array elem

    "MPPB_SKOutgoingRatchet": {1: ("ratchetState", "bytes"),
        2: ("privateSigningKey", "bytes"),
        3: ("currentMessageKey", "MPPB_KeyAndIndex"),
        4: ("subscriptionKey", "MPPB_KeyAndIndex")},
    "MPPB_SKIncomingRatchet": {1: ("ratchetState", "bytes"),
        2: ("messageKeys", "repeated MPPB_KeyAndIndex"),   # #69: symref array elem
        3: ("publicSigningKey", "bytes")},
    "MPPB_SKPaddedStatus": {1: ("payload", "bytes"), 2: ("padding", "bytes")},
}

CREATEML = {
    "CoreML_Metadata": {1: ("shortDescription", "string"),
        2: ("versionString", "string"), 3: ("author", "string"),
        4: ("license", "string"),
        100: ("userDefined", "map<string, string>")},  # #66 fixed: S2S run-length subst decoded
    "CoreML_NearestNeighborsIndex": {1: ("numberOfDimensions", "int32"),
        2: ("floatSamples", "repeated CoreML_FloatVector"),   # resolved repeated-message ✓
        100: ("linearIndex", "CoreML_LinearIndex"),           # oneof members (#60 resolved)
        110: ("singleKdTreeIndex", "CoreML_SingleKdTreeIndex"),
        200: ("squaredEuclideanDistance", "CoreML_SquaredEuclideanDistance")},
}


def _load_cache(framework):
    from macho.dyld_cache import DyldCacheReader
    from macho.memory import BinaryContext
    reader = DyldCacheReader(_cache_path())
    try:
        ctx = BinaryContext.from_cache(reader, reader.find_image_header(framework))
        return _by_number(SW.swift_messages(ctx))
    finally:
        reader.close()


@unittest.skipUnless(_cache_path(), "dyld cache (+ .symbols) not available")
class TestCacheGroundTruth(unittest.TestCase):
    def _check(self, framework, truth):
        got = _load_cache(framework)
        for msg, fields in truth.items():
            self.assertIn(msg, got, f"{framework}: message {msg} missing")
            for num, (name, ptype) in fields.items():
                self.assertIn(num, got[msg], f"{framework} {msg}: #{num} missing")
                gname, gtype = got[msg][num]
                self.assertEqual(gname, name,
                                 f"{framework} {msg} #{num}: name {gname!r} != {name!r}")
                self.assertEqual(gtype, ptype,
                                 f"{framework} {msg} #{num} ({name}): type "
                                 f"{gtype!r} != expected {ptype!r}")

    def test_siri_task_engagement(self):
        self._check("SiriTaskEngagement", SIRI)

    def test_message_protection(self):
        self._check("MessageProtection", MESSAGE_PROTECTION)

    def test_createml_map_and_repeated_message(self):
        self._check("CreateML", CREATEML)


@unittest.skipUnless(_remindd_path(), "remindd binary not available")
class TestRuntimeNameMap(unittest.TestCase):
    """#72/#71: messages whose nameMap is emitted as a runtime-built _NameMap
    (the once-init ``cmn x?,#1; b.ne <builder>`` form) carry their complete
    (number, name) table literally in the cold builder closure.  Reading it
    recovers every field with a confirmed number — both app types (Credential,
    previously shape-B under-read to its first field) and the SwiftProtobuf
    well-known types (previously empty / single-field)."""
    @classmethod
    def setUpClass(cls):
        from macho.memory import BinaryContext
        with open(_remindd_path(), "rb") as fh:
            data = SW.load_macho_slice(fh.read())
        cls.ctx = BinaryContext(data)
        cls.msgs = {m.name: m for m in SW.swift_messages(cls.ctx)}

    def test_credential_full_five_fields(self):
        m = self.msgs["StartMigrationRequest.Credential"]
        self.assertEqual(
            [(f.number, f.name, f.proto_type) for f in m.fields],
            [(1, "dsID", "string"), (2, "baseURL", "string"),
             (3, "hostname", "string"), (4, "mmeAuthToken", "string"),
             (5, "partition", "uint32")])
        self.assertTrue(all(f.number_confirmed for f in m.fields))

    def test_well_known_type_field_numbers(self):
        # The recovered tables reproduce the canonical google.protobuf schemas
        # exactly (independent validation): Any = type_url/value; Duration =
        # seconds/nanos; Method = #1-7; EnumValue = name/number/options.
        def nums(name):
            return {f.number: f.name for f in self.msgs[name].fields}
        self.assertEqual(nums("Google_Protobuf_Any"), {1: "type_url", 2: "value"})
        self.assertEqual(nums("Google_Protobuf_Duration"), {1: "seconds", 2: "nanos"})
        self.assertEqual(nums("Google_Protobuf_EnumValue"),
                         {1: "name", 2: "number", 3: "options"})
        self.assertEqual(nums("Google_Protobuf_Method"),
                         {1: "name", 2: "request_type_url", 3: "request_streaming",
                          4: "response_type_url", 5: "response_streaming",
                          6: "options", 7: "syntax"})
        # Field exercises every builder store-shape: #1-10 combined-stp, #4 has
        # number == len(name) (resolved by operand position), #11 split-str tail.
        self.assertEqual(nums("Google_Protobuf_Field"),
                         {1: "kind", 2: "cardinality", 3: "number", 4: "name",
                          6: "type_url", 7: "oneof_index", 8: "packed",
                          9: "options", 10: "json_name", 11: "default_value"})
        self.assertTrue(all(f.number_confirmed
                            for f in self.msgs["Google_Protobuf_Method"].fields))

    def test_cow_storage_field_types(self):
        # #60: fields moved into the COW _StorageClass are linked back to the
        # message via the descriptor parent chain and typed from its fieldmd.
        d = {f.name: f.proto_type for f in self.msgs["MigrateRequest"].fields}
        self.assertEqual(d["options"], "uint32")
        self.assertEqual(d["user_initiated"], "bool")
        self.assertEqual(d["simulated_error"], "int32")
        det = {f.name: f.proto_type
               for f in self.msgs["MigrateResponse.Details"].fields}
        self.assertEqual(det["time_elapsed"], "double")
        self.assertEqual(det["is_observer"], "bool")

    def test_oneof_member_types(self):
        # #60: each proto oneof is a nested OneOf_<name> enum whose cases carry
        # the member payload type; resolved and bound by member name.
        val = {f.number: (f.name, f.proto_type)
               for f in self.msgs["Google_Protobuf_Value"].fields}
        self.assertEqual(val[2], ("number_value", "double"))
        self.assertEqual(val[4], ("bool_value", "bool"))
        self.assertEqual(val[5], ("struct_value", "Google_Protobuf_Struct"))
        smr = {f.name: f.proto_type
               for f in self.msgs["StartMigrationRequest"].fields}
        self.assertEqual(smr["archivePath"], "string")
        self.assertEqual(smr["credential"], "StartMigrationRequest.Credential")   # nested message member (qualified)

    def test_string_array_element_recovered(self):
        # Google_Protobuf_Type.oneofs is `repeated string` (google/protobuf/type.proto): the
        # `[String]` element (SaySSG) is read, not left a flagged `bytes` filler (#124; the
        # filler and its note for an element that does not resolve: test_swift_type_recovery).
        # remindd's fields are typed by name (stripped): that note alone, no container's (#130)
        byname = {f.name: f for f in self.msgs["Google_Protobuf_Type"].fields}
        self.assertEqual(byname["oneofs"].proto_type, "repeated string")
        for name in ("oneofs", "name", "fields"):               # (fields: repeated <msg>)
            self.assertEqual(byname[name].type_note, SW._BY_NAME_NOTE, name)

    def test_qualified_keys_avoid_short_name_collision(self):
        # #68: the field-type map keys by QUALIFIED name, so the three distinct
        # `Details` nested types (Migrate/StartMigration/Unmigrate Response) stay
        # separate instead of merging.  UnmigrateResponse.Details genuinely differs
        # (only timeElapsed) — short-name keying would have merged the other two's
        # fields onto it.
        from serializers import swift_type_recovery as TR
        bt = TR.collect_field_types(self.ctx)[0]
        details = {k: v for k, v in bt.items() if k.split(".")[-1] == "Details"}
        self.assertGreaterEqual(len(details), 2, "Details types should not be merged")
        self.assertIn("MigrateResponse.Details", details)
        self.assertIn("UnmigrateResponse.Details", details)
        self.assertEqual(set(details["UnmigrateResponse.Details"]), {"timeElapsed"})
        self.assertIn("isObserver", details["MigrateResponse.Details"])

    def test_field_fully_recovered_all_confirmed(self):
        # #71: the unified builder reader recovers Google_Protobuf_Field COMPLETELY
        # (10/10, incl. the #11 split-str tail), every number literal -> confirmed.
        # (Was previously rejected as a 9/10 incomplete read.)  The cross-validation
        # guard's own logic is covered by TestNameMapBuilderValidation.
        m = self.msgs["Google_Protobuf_Field"]
        self.assertEqual(len(m.fields), 10)
        self.assertTrue(all(f.number_confirmed for f in m.fields))
