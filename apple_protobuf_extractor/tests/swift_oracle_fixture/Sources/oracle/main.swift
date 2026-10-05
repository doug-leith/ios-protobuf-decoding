import Foundation
import SwiftProtobuf

var s7 = Ora_Single7()
s7.only = "seven"

var s1 = Ora_Single1()
s1.only = "one"

var multi = Ora_Multi()
multi.a = 1
multi.b = "b"
multi.c = true
multi.big = 5
multi.raw = Data([0x01, 0x02])

var wk = Ora_WithKinds()
wk.nums = [1, 2, 3]
wk.child = s1
wk.lut = ["k": 1]
wk.zig = -1
wk.fx = 42

var total = 0
for data in [try! s7.serializedData(), try! s1.serializedData(),
             try! multi.serializedData(), try! wk.serializedData()] {
    total += data.count
}
print("oracle serialized \(total) bytes")
