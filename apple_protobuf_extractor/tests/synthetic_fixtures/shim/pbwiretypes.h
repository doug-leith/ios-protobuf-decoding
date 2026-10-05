// Extern declarations for the hand-assembled wire-type-family write helpers
// in pbwiretypes.s (see that file + ../README.md gotcha 6). Plain C linkage,
// same calling convention as pbshim.h's field helpers.
#import "pbshim.h"

extern void PBWriteSInt32Field(PBDataWriter *writer, int32_t value, uint32_t tag);
extern void PBWriteSInt64Field(PBDataWriter *writer, int64_t value, uint32_t tag);
extern void PBWriteFixed32Field(PBDataWriter *writer, uint32_t value, uint32_t tag);
extern void PBWriteFixed64Field(PBDataWriter *writer, uint64_t value, uint32_t tag);
