// Two avianlink engines exchanging a message through the C ABI from Swift.
// Run: scripts/swift-smoke-test.sh

import Avianlink
import Foundation

func check(_ st: AvlStatus, _ what: String, line: Int = #line) {
    if st != AVL_STATUS_OK {
        fatalError("\(what) -> \(st.rawValue) (engine error \(avl_last_engine_error().rawValue)) at line \(line)")
    }
}

final class Node {
    var engine: OpaquePointer?
    var secret = [UInt8](repeating: 0, count: 32)
    var publicKey = [UInt8](repeating: 0, count: 32)
    var peer = [UInt8](repeating: 0, count: 16)

    init() {
        check(avl_identity_generate(&secret, &publicKey), "generate")
        var storage: OpaquePointer?
        check(avl_storage_memory_new(&storage), "storage")
        check(avl_engine_open(secret, storage, nil, &engine), "open")
        var link = AvlLinkConfig()
        link.mtu = 200
        link.cost = 1
        link.budget = UInt8(AVL_BUDGET_KIND_UNLIMITED.rawValue)
        check(avl_engine_add_link(engine, 1, &link), "add_link")
    }

    deinit { avl_engine_free(engine) }

    func fingerprint() -> String {
        var out = [CChar](repeating: 0, count: 25)
        check(avl_fingerprint(publicKey, &out), "fingerprint")
        return String(cString: out)
    }

    func send(_ text: String, now: UInt64) {
        let bytes = Array(text.utf8)
        var q = AvlQueued()
        check(avl_engine_send_text(engine, peer, bytes, bytes.count, now, &q), "send")
    }

    func deliver(to other: Node, now: UInt64) {
        var buf = [UInt8](repeating: 0, count: 200)
        while true {
            var link: UInt16 = 0
            var len = 0
            let st = avl_engine_poll_transmit(engine, now, &link, nil, &buf, buf.count, &len)
            if st == AVL_STATUS_NONE { return }
            check(st, "poll_transmit")
            // OK, or NONE for a Hello from a contact `other` already knows.
            let rx = avl_engine_handle_packet(other.engine, link, buf, len, now, nil, nil)
            if rx != AVL_STATUS_OK && rx != AVL_STATUS_NONE { check(rx, "handle_packet") }
        }
    }

    func received() -> [String] {
        var out: [String] = []
        var ev = AvlEvent()
        while avl_engine_poll_event(engine, &ev) == AVL_STATUS_OK {
            if ev.kind == AVL_EVENT_KIND_MESSAGE_RECEIVED {
                // Borrowed until the next poll: copy now.
                out.append(String(cString: ev.text))
            }
        }
        return out
    }
}

let alice = Node()
let bob = Node()
print("alice \(alice.fingerprint()), bob \(bob.fingerprint())")
check(avl_engine_add_contact(alice.engine, bob.publicKey, &alice.peer), "contact")
check(avl_engine_add_contact(bob.engine, alice.publicKey, &bob.peer), "contact")

var now = UInt64(Date().timeIntervalSince1970 * 1000)
alice.send("hello from Swift 🐦", now: now)
var got: [String] = []
for _ in 0..<20 {
    alice.deliver(to: bob, now: now)
    bob.deliver(to: alice, now: now)
    got += bob.received()
    _ = alice.received()
    now += 100
    avl_engine_handle_timeout(alice.engine, now)
    avl_engine_handle_timeout(bob.engine, now)
}
guard got == ["hello from Swift 🐦"], avl_engine_outbox_len(alice.engine) == 0 else {
    fatalError("FAIL: \(got), outbox \(avl_engine_outbox_len(alice.engine))")
}
print("bob received: \(got[0])")
print("ok")
