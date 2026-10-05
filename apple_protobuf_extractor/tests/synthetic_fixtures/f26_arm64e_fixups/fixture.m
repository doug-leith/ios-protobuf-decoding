#import <Foundation/Foundation.h>

// Minimal ObjC class, built arm64e, purely to give macho/memory.py's
// chained-fixup decoder a real DYLD_CHAINED_PTR_ARM64E_USERLAND24 image to
// decode: classlist / method-list / selref rebases (some authenticated), a
// classref bind, __objc_data binds with PAC diversifiers, and __auth_got
// binds. The ground truth is Apple's own `dyld_info -fixups` output for the
// built binary, recorded in expected.py — not the extractor's output.

@interface TestFixupClass : NSObject
- (id)make;
@end

@implementation TestFixupClass
- (id)make { return [NSMutableArray new]; }
@end

int main(void) { return 0; }
