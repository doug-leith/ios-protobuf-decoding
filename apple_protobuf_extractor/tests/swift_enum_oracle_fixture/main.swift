import Foundation
import SwiftProtobuf
var h = Eo_Holder()
h.top = .tNeg; h.inner = .iB; h.nz = [.nzSeven]; h.al = .alY; h.single = .only; h.plain = "x"
var m = Eo_Multi()
m.a = 1; m.b = "b"; m.c = true; m.n10 = 10; m.t = .tBig; m.big = 5
print(try! h.serializedData().count + (try! m.serializedData().count), Eo_Aliased.alY2, Eo_Top.allCases.count)
