package com.github.h3yow.springsessionrbacjava.tests;

import com.github.h3yow.springsessionrbacjava.session.RevocationReason;
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
        assertEquals(2, store.activeCount("alice"), "被挤掉的会话立即释放名额");
        SessionRecord evicted = store.find(s1.id()).orElseThrow();
        assertTrue(evicted.isRevoked(), "最旧会话应被挤下线并保留墓碑");
        assertEquals(RevocationReason.CAP_EVICTED, evicted.revocationReason(),
                "被挤掉的原因必须可分辨为 CAP_EVICTED");
        assertTrue(store.find(s2.id()).isPresent());
        assertTrue(store.find(s3.id()).isPresent());
        assertFalse(store.renew(s1.id(), 3600), "被挤掉的会话不得续期复活");
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
    @Test
    void listActiveIsSortedAndExcludesTombsAndOtherUsers() {
        SessionStore store = new SessionStore();
        SessionRecord a1 = store.create("alice", 3600, 5);
        SessionRecord a2 = store.create("alice", 3600, 5);
        SessionRecord b1 = store.create("bob", 3600, 5);

        var alice = store.listActive("alice");
        assertEquals(2, alice.size());
        assertEquals(a1.id(), alice.get(0).id(), "按创建时间升序");
        assertEquals(a2.id(), alice.get(1).id());
        assertEquals(1, store.listActive("bob").size(), "只含本人会话");

        // 下线后立即从活跃列表消失，但 find 仍能找到墓碑（原因可分辨）
        store.revoke(a1.id(), RevocationReason.USER_TERMINATED);
        assertEquals(1, store.listActive("alice").size());
        SessionRecord tomb = store.find(a1.id()).orElseThrow();
        assertTrue(tomb.isRevoked());
        assertEquals(RevocationReason.USER_TERMINATED, tomb.revocationReason());
        log.info("list/tomb ok: active={}, tombReason={}", store.listActive("alice").size(),
                tomb.revocationReason());
    }

    @Test
    void terminateFreesSlotAndReasonIsStableUnderRepeatedCalls() {
        SessionStore store = new SessionStore();
        SessionRecord s1 = store.create("alice", 3600, 2);
        SessionRecord s2 = store.create("alice", 3600, 2);
        assertEquals(2, store.activeCount("alice"));

        // 属主校验下线
        assertEquals(SessionStore.OwnedRevokeResult.REVOKED,
                store.revokeIfOwner("alice", s1.id(), RevocationReason.USER_TERMINATED));
        assertEquals(1, store.activeCount("alice"), "下线立即释放名额");
        // 名额可重新占上
        SessionRecord s3 = store.create("alice", 3600, 2);
        assertEquals(2, store.activeCount("alice"));
        assertTrue(store.find(s2.id()).filter(r -> !r.isRevoked()).isPresent(), "不应误伤兄弟会话");

        // 重复下线：幂等，首次原因不被覆盖
        assertEquals(SessionStore.OwnedRevokeResult.REVOKED,
                store.revokeIfOwner("alice", s1.id(), RevocationReason.CAP_EVICTED));
        assertEquals(RevocationReason.USER_TERMINATED, store.find(s1.id()).orElseThrow().revocationReason());

        // 非属主/不存在：统一 NOT_FOUND，且别人的会话不被动
        assertEquals(SessionStore.OwnedRevokeResult.NOT_FOUND,
                store.revokeIfOwner("bob", s2.id(), RevocationReason.USER_TERMINATED));
        assertEquals(SessionStore.OwnedRevokeResult.NOT_FOUND,
                store.revokeIfOwner("alice", "nope", RevocationReason.USER_TERMINATED));
        assertTrue(store.find(s2.id()).filter(r -> !r.isRevoked()).isPresent(),
                "越权下线不得触碰他人/他会话");

        // 一键下线其他：保留指定会话
        int n = store.revokeOthers("alice", s3.id(), RevocationReason.USER_TERMINATED);
        assertEquals(1, n, "s2 被下线");
        assertTrue(store.find(s3.id()).filter(r -> !r.isRevoked()).isPresent(), "保留会话仍活跃");
        assertEquals(1, store.activeCount("alice"));
        log.info("terminate slot/reason/ownership checks ok");
    }

    @Test
    void tombstoneIsPurgedAfterRetentionAndThenLooksMissing() {
        SessionStore store = new SessionStore();
        store.setTombstoneTtlSeconds(0); // 保留期为 0：任何惰性清扫都会清掉墓碑
        SessionRecord s1 = store.create("alice", 3600, 2);
        store.revoke(s1.id());
        // 触发该用户的惰性清扫（activeCount 内部 sweep）
        assertEquals(0, store.activeCount("alice"));
        assertTrue(store.find(s1.id()).isEmpty(), "保留期过后墓碑彻底消失，与伪造 ID 不可区分");
        log.info("tombstone purged after retention, find=empty");

        // 过期非墓碑记录：保留宽限结束后同样被清扫
        SessionStore store2 = new SessionStore();
        store2.setTombstoneTtlSeconds(0);
        SessionRecord expired = store2.create("alice", 0, 2);
        assertEquals(0, store2.activeCount("alice"), "过期不占名额并触发清扫");
        assertTrue(store2.find(expired.id()).isEmpty());
    }

    @Test
    void touchUpdatesLastAccessOnlyWhileActive() throws InterruptedException {
        SessionStore store = new SessionStore();
        SessionRecord s = store.create("alice", 3600, 2);
        Thread.sleep(5);
        store.touch(s.id());
        assertTrue(store.find(s.id()).orElseThrow().lastAccessAt().isAfter(s.createdAt()),
                "活跃访问应推进最近活动时间");
        store.revoke(s.id());
        var at = store.find(s.id()).orElseThrow().lastAccessAt();
        store.touch(s.id());
        assertEquals(at, store.find(s.id()).orElseThrow().lastAccessAt(), "墓碑不更新活动时间");
    }
}
