package com.github.h3yow.springsessionrbacjava.tests;

import com.github.h3yow.springsessionrbacjava.session.SessionRecord;
import com.github.h3yow.springsessionrbacjava.session.SessionStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class SessionStoreTest {

    private static final Logger log = LoggerFactory.getLogger(SessionStoreTest.class);

    @Test
    void capEvictsOldestSession() {
        SessionStore store = new SessionStore();
        SessionRecord s1 = store.create("alice", 3600, 2);
        SessionRecord s2 = store.create("alice", 3600, 2);
        SessionRecord s3 = store.create("alice", 3600, 2);
        log.info("cap=2, created=[{},{},{}], activeCount={}", s1.id(), s2.id(), s3.id(),
                store.activeCount("alice"));
        assertEquals(2, store.activeCount("alice"));
        assertTrue(store.find(s1.id()).isEmpty(), "最旧会话应被淘汰");
        assertTrue(store.find(s1.id()).map(SessionRecord::isRevoked).orElse(true));
        assertTrue(store.find(s2.id()).isPresent());
        assertTrue(store.find(s3.id()).isPresent());
    }

    @Test
    void expiredSessionIsEvictedAndNotRenewable() {
        SessionStore store = new SessionStore();
        SessionRecord s = store.create("alice", 0, 2); // ttl=0 立即过期
        log.info("ttl=0, expired={}", s.isExpired(java.time.Instant.now()));
        assertEquals(0, store.activeCount("alice"));
        assertFalse(store.renew(s.id(), 3600), "过期会话不得续期复活");
    }

    @Test
    void renewExtendsLivingSession() {
        SessionStore store = new SessionStore();
        SessionRecord s = store.create("alice", 3600, 2);
        assertTrue(store.renew(s.id(), 7200));
        log.info("renew ok, newExpiry={}", store.find(s.id()).orElseThrow().expiresAt());
        assertFalse(store.renew("nonexistent", 7200));
    }

    @Test
    void revokeIsIdempotent() {
        SessionStore store = new SessionStore();
        SessionRecord s = store.create("alice", 3600, 2);
        assertTrue(store.revoke(s.id()));
        assertFalse(store.revoke(s.id()), "重复注销返回稳定结果");
        assertFalse(store.renew(s.id(), 3600), "已注销会话不得续期");
        log.info("revoke idempotent ok, sessionId={}", s.id());
    }

    @Test
    void concurrentLoginsRespectCapAndNeverMixUsers() throws InterruptedException {
        SessionStore store = new SessionStore();
        int threads = 16;
        int cap = 3;
        Set<String> aliceSessions = ConcurrentHashMap.newKeySet();
        Set<String> bobSessions = ConcurrentHashMap.newKeySet();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        for (int i = 0; i < threads; i++) {
            String user = (i % 2 == 0) ? "alice" : "bob";
            Set<String> sink = (i % 2 == 0) ? aliceSessions : bobSessions;
            pool.submit(() -> {
                try {
                    start.await();
                    SessionRecord r = store.create(user, 3600, cap);
                    sink.add(r.id());
                    assertEquals(user, r.username(), "会话不得串号");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("concurrent create: threads={}, cap={}, aliceActive={}, bobActive={}",
                threads, cap, store.activeCount("alice"), store.activeCount("bob"));
        assertEquals(cap, store.activeCount("alice"));
        assertEquals(cap, store.activeCount("bob"));
        assertEquals(threads / 2, aliceSessions.size(), "每次登录必须签发全新会话 ID");
        assertEquals(threads / 2, bobSessions.size());
        assertTrue(java.util.Collections.disjoint(aliceSessions, bobSessions), "两账号会话不得交叉");
    }
}
