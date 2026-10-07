package com.github.h3yow.springsessionrbacjava.tests;

import com.github.h3yow.springsessionrbacjava.session.SessionLookup;
import com.github.h3yow.springsessionrbacjava.session.SessionRecord;
import com.github.h3yow.springsessionrbacjava.session.SessionStore;
import com.github.h3yow.springsessionrbacjava.session.TerminationReason;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 场景二的并发竞争：登录、定向下线、续期、一键下线混合并发下，
 * 名额与上限始终一致、不串号、不误伤，且终态原因由首次终止确定。
 */
class SessionStoreConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(SessionStoreConcurrencyTest.class);

    @Test
    void mixedLoginRevokeRenewStaysConsistentAndWithinCap() throws InterruptedException {
        SessionStore store = new SessionStore();
        int cap = 2;
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger errors = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    String user = (idx % 2 == 0) ? "alice" : "bob";
                    SessionRecord r = store.create(user, 3600, cap);
                    assertEquals(user, r.username(), "会话不得串号");
                    // 三种操作混合：续期、下线自己、再登录占回名额
                    store.renew(r.id(), 3600);
                    store.revoke(r.id());
                    SessionRecord r2 = store.create(user, 3600, cap);
                    store.renew(r2.id(), 3600);
                    // 不变量：任何时刻名下活跃会话数不得超过上限（这里取最终及中间采样点）
                    if (store.activeCount(user) > cap) {
                        errors.incrementAndGet();
                    }
                } catch (Throwable t) {
                    log.error("worker error", t);
                    errors.incrementAndGet();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(15, TimeUnit.SECONDS));
        assertEquals(0, errors.get(), "并发过程不得出现越上限/串号/异常");
        log.info("mixed concurrency done: aliceActive={}, bobActive={}",
                store.activeCount("alice"), store.activeCount("bob"));
        assertTrue(store.activeCount("alice") <= cap);
        assertTrue(store.activeCount("bob") <= cap);
    }

    @Test
    void capSlotReleasedByRevokeIsReusableUnderConcurrentLogin() throws InterruptedException {
        SessionStore store = new SessionStore();
        int cap = 3;
        // 先占满
        Set<String> initial = ConcurrentHashMap.newKeySet();
        for (int i = 0; i < cap; i++) {
            initial.add(store.create("alice", 3600, cap).id());
        }
        assertEquals(cap, store.activeCount("alice"));

        // 并发：一半线程下线旧会话，一半线程登录
        int n = 12;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        Set<String> evictedOrRevoked = ConcurrentHashMap.newKeySet();
        for (int i = 0; i < n; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    if (idx % 2 == 0) {
                        String victim = initial.stream().findAny().orElse(null);
                        if (victim != null) {
                            store.revoke(victim);
                        }
                    } else {
                        SessionRecord r = store.create("alice", 3600, cap);
                        evictedOrRevoked.add(r.id());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(15, TimeUnit.SECONDS));
        int finalCount = store.activeCount("alice");
        log.info("release/reuse race finished: activeCount={}, cap={}", finalCount, cap);
        assertEquals(cap, finalCount, "下线释放的名额被重新占用后，数量必须与上限精确对齐");
    }

    @Test
    void firstTerminationReasonWinsUnderRace() throws InterruptedException {
        SessionStore store = new SessionStore();
        int n = 8;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        SessionRecord s = store.create("alice", 1, 2); // 1 秒后过期
        Thread.sleep(1100);
        for (int i = 0; i < n; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    store.revoke(s.id()); // 与过期判定竞争
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        SessionLookup lookup = store.lookup(s.id());
        assertEquals(SessionLookup.State.TERMINATED, lookup.state());
        assertEquals(TerminationReason.EXPIRED, lookup.reason(),
                "自然过期先发生时，后到的注销不得把原因改写为 LOGOUT");
        log.info("termination reason preserved under race: {}", lookup.reason());
    }
}
