/* Two avianlink engines in one process, exchanging a message over an
 * in-memory "link". Build: scripts/c-example.sh */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "avianlink.h"

#define LINK 1
#define MTU 200

#define CHECK(call)                                                        \
    do {                                                                   \
        AvlStatus st_ = (call);                                            \
        if (st_ != AVL_STATUS_OK) {                                        \
            fprintf(stderr, "%s:%d: %s -> %d (engine error %d)\n",         \
                    __FILE__, __LINE__, #call, (int)st_,                   \
                    (int)avl_last_engine_error());                         \
            exit(1);                                                       \
        }                                                                  \
    } while (0)

typedef struct {
    AvlEngine *engine;
    uint8_t secret[32];
    uint8_t public_key[32];
    uint8_t peer[16]; /* conversation with the other node */
} Node;

static void node_open(Node *n) {
    AvlStorage *storage = NULL;
    AvlLinkConfig link = {0};
    char fp[25];

    CHECK(avl_identity_generate(n->secret, n->public_key));
    CHECK(avl_storage_memory_new(&storage));
    CHECK(avl_engine_open(n->secret, storage, NULL, &n->engine));
    link.mtu = MTU;
    link.cost = 1;
    link.budget = AVL_BUDGET_KIND_UNLIMITED;
    CHECK(avl_engine_add_link(n->engine, LINK, &link));
    CHECK(avl_fingerprint(n->public_key, fp));
    printf("node %s\n", fp);
}

/* Moves every packet `from` wants to send into `to`. */
static int deliver(Node *from, Node *to, uint64_t now) {
    uint8_t buf[MTU];
    int n = 0;
    for (;;) {
        uint16_t link;
        size_t len;
        AvlStatus st = avl_engine_poll_transmit(from->engine, now, &link, NULL,
                                                buf, sizeof buf, &len);
        if (st == AVL_STATUS_NONE) return n;
        CHECK(st);
        st = avl_engine_handle_packet(to->engine, link, buf, len, now, NULL);
        if (st != AVL_STATUS_OK) {
            fprintf(stderr, "packet not authenticated\n");
            exit(1);
        }
        n++;
    }
}

/* Prints events; returns how many messages arrived. */
static int drain(const char *who, Node *n) {
    AvlEvent ev;
    int received = 0;
    while (avl_engine_poll_event(n->engine, &ev) == AVL_STATUS_OK) {
        switch (ev.kind) {
        case AVL_EVENT_KIND_MESSAGE_RECEIVED:
            printf("%s received seq %llu: %.*s\n", who,
                   (unsigned long long)ev.seq, (int)ev.text_len, ev.text);
            received++;
            break;
        case AVL_EVENT_KIND_MESSAGE_DELIVERED:
            printf("%s: delivered\n", who);
            break;
        case AVL_EVENT_KIND_MESSAGE_TRANSMITTED:
            printf("%s: transmitted\n", who);
            break;
        default:
            printf("%s: event %d\n", who, (int)ev.kind);
        }
    }
    return received;
}

int main(void) {
    Node alice = {0}, bob = {0};
    AvlQueued q;
    const char *hello = "hello from C";
    const char *reply = "hello back";
    uint64_t now = 1700000000000ull;
    int got_a = 0, got_b = 0;

    node_open(&alice);
    node_open(&bob);
    CHECK(avl_engine_add_contact(alice.engine, bob.public_key, alice.peer));
    CHECK(avl_engine_add_contact(bob.engine, alice.public_key, bob.peer));

    CHECK(avl_engine_send_text(alice.engine, alice.peer, (const uint8_t *)hello,
                               strlen(hello), now, &q));
    CHECK(avl_engine_send_text(bob.engine, bob.peer, (const uint8_t *)reply,
                               strlen(reply), now, &q));

    for (int round = 0; round < 20; round++) {
        uint64_t t;
        deliver(&alice, &bob, now);
        deliver(&bob, &alice, now);
        got_b += drain("bob", &bob);
        got_a += drain("alice", &alice);
        now += 100;
        if (avl_engine_next_timeout(alice.engine, &t) && t <= now)
            CHECK(avl_engine_handle_timeout(alice.engine, now));
        if (avl_engine_next_timeout(bob.engine, &t) && t <= now)
            CHECK(avl_engine_handle_timeout(bob.engine, now));
    }

    if (avl_engine_outbox_len(alice.engine) != 0 || avl_engine_outbox_len(bob.engine) != 0 ||
        got_a != 1 || got_b != 1) {
        fprintf(stderr, "FAIL: alice got %d, bob got %d\n", got_a, got_b);
        return 1;
    }
    avl_engine_free(alice.engine);
    avl_engine_free(bob.engine);
    printf("ok\n");
    return 0;
}
