package com.github.h3yow.springsessionrbacjava.session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 并发安全的内存会话存储。
 * <ul>
 *   <li>同账号并发会话上限可配置，超出时按稳定策略淘汰该账号最旧会话（终止原因 CAP_EVICTED）；</li>
 *   <li>按用户名加锁，保证并发登录/注销/续期/下线不产生串号或不可恢复状态；</li>
 *   <li>会话 ID 与 CSRF 令牌由 CSPRNG 生成，每次登录签发全新 ID（防会话固定）；</li>
 *   <li>被终止（注销/挤掉/过期）的会话进入墓碑表并保留原因：旧会话再次访问或续期时，
 *       各入口给出一致且可区分的结论；墓碑保留期过后惰性清理。</li>
 * </ul>
 */
@Component
public class SessionStore {

    private static final Logger log = LoggerFactory.getLogger(SessionStore.class);

    /** 墓碑保留时长：终止后 24h 内旧会话再次访问仍能给出准确原因，之后退化为 SESSION_MISSING。 */
    static final long TOMBSTONE_TTL_SECONDS = 24 * 3600L;
    /** 墓碑表惰性清理的容量阈值，避免无限增长。 */
    private static final int TOMBSTONE_SWEEP_THRESHOLD = 10_000;

    private final ConcurrentHashMap<String, SessionRecord> byId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, SessionRecord> tombstones = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> idsByUser = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ReentrantLock> userLocks = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    private String newToken() {
        byte[] buf = new byte[32];
        random.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private ReentrantLock lockFor(String username) {
        return userLocks.computeIfAbsent(username, u -> new ReentrantLock());
    }

    /**
     * 创建会话。先惰性清理该账号的过期会话；若仍达上限，淘汰最旧会话
     * （稳定策略，按 createdAt 升序、id 兜底），其终止原因为 CAP_EVICTED，名额立即释放。
     */
    public SessionRecord create(String username, long ttlSeconds, int maxConcurrentSessions) {
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            Set<String> ids = idsByUser.computeIfAbsent(username, u -> ConcurrentHashMap.newKeySet());
            evictExpiredLocked(ids);
            while (ids.size() >= maxConcurrentSessions) {
                String oldest = ids.stream()
                        .map(byId::get)
                        .filter(r -> r != null)
                        .min(Comparator.comparing(SessionRecord::createdAt)
                                .thenComparing(SessionRecord::id))
                        .map(SessionRecord::id)
                        .orElse(null);
                if (oldest == null) {
                    break;
                }
                SessionRecord evicted = terminateLocked(ids, oldest, TerminationReason.CAP_EVICTED);
                log.info("cap eviction: username={}, evictedSessionId={}, cap={}",
                        username, evicted.id(), maxConcurrentSessions);
            }
            Instant now = Instant.now();
            SessionRecord record = new SessionRecord(newToken(), username, newToken(),
                    now, now.plusSeconds(ttlSeconds));
            byId.put(record.id(), record);
            ids.add(record.id());
            return record;
        } finally {
            lock.unlock();
        }
    }

    /**
     * 仅查找活跃表中的原始记录（可能已自然过期但尚未惰性清理）。
     * 用于 CSRF 过滤器：失效会话放行给下游认证逻辑给出统一结论。
     */
    public Optional<SessionRecord> find(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byId.get(sessionId));
    }

    /**
     * 会话状态机查找，在该会话所属账号的锁内完成，防止"读取与判定之间被终止/过期"的竞争：
     * <ul>
     *   <li>活跃且未过期 → ACTIVE，并惰性更新过期判定；</li>
     *   <li>已终止（墓碑表内，仍在保留期）→ TERMINATED + 终止原因；</li>
     *   <li>不存在/伪造/墓碑已过保留期 → UNKNOWN（不携带任何信息）。</li>
     * </ul>
     */
    public SessionLookup lookup(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return SessionLookup.unknown();
        }
        SessionRecord active = byId.get(sessionId);
        if (active != null) {
            ReentrantLock lock = lockFor(active.username());
            lock.lock();
            try {
                SessionRecord still = byId.get(sessionId);
                if (still != active) {
                    // 持锁期间被并发移走：重读墓碑/缺失结论。
                    if (still != null) {
                        return SessionLookup.active(still);
                    }
                    return lookupTombstone(sessionId);
                }
                Instant now = Instant.now();
                if (active.isExpired(now)) {
                    terminateLocked(idsByUser.get(active.username()), sessionId, TerminationReason.EXPIRED);
                    log.info("session expired on access: username={}, sessionId={}",
                            active.username(), sessionId);
                    return SessionLookup.terminated(active, TerminationReason.EXPIRED);
                }
                return SessionLookup.active(active);
            } finally {
                lock.unlock();
            }
        }
        return lookupTombstone(sessionId);
    }

    private SessionLookup lookupTombstone(String sessionId) {
        sweepTombstonesIfNeeded();
        SessionRecord dead = tombstones.get(sessionId);
        if (dead == null) {
            return SessionLookup.unknown();
        }
        if (dead.terminatedAt() != null
                && dead.terminatedAt().isBefore(Instant.now().minusSeconds(TOMBSTONE_TTL_SECONDS))) {
            tombstones.remove(sessionId, dead);
            return SessionLookup.unknown();
        }
        return SessionLookup.terminated(dead, dead.terminationReason());
    }

    /**
     * 注销/定向下线，幂等：仅当会话当前处于活跃表时完成一次终止（原因 LOGOUT），
     * 并立即释放名下名额。重复注销/已过期/不存在均返回 false，且不改变既有终止原因。
     */
    public boolean revoke(String sessionId) {
        SessionRecord record = byId.get(sessionId);
        if (record == null) {
            return false;
        }
        ReentrantLock lock = lockFor(record.username());
        lock.lock();
        try {
            SessionRecord still = byId.get(sessionId);
            if (still == null) {
                return false;
            }
            Instant now = Instant.now();
            if (still.isExpired(now)) {
                // 自然过期优先于并发注销，保持"为什么失效"的结论准确。
                terminateLocked(idsByUser.get(record.username()), sessionId, TerminationReason.EXPIRED);
                return false;
            }
            terminateLocked(idsByUser.get(record.username()), sessionId, TerminationReason.LOGOUT);
            log.info("session revoked: username={}, sessionId={}", record.username(), sessionId);
            return true;
        } finally {
            lock.unlock();
        }
    }

    /** 注销某账号全部活跃会话（原因 LOGOUT），返回被终止的会话数。 */
    public int revokeAll(String username) {
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            Set<String> ids = idsByUser.get(username);
            if (ids == null || ids.isEmpty()) {
                return 0;
            }
            int n = 0;
            for (String id : new ArrayList<>(ids)) {
                if (terminateLocked(ids, id, TerminationReason.LOGOUT) != null) {
                    n++;
                }
            }
            return n;
        } finally {
            lock.unlock();
        }
    }

    /**
     * 下线某账号除 keepSessionId 以外的全部活跃会话（原因 LOGOUT），返回被终止的会话数。
     * keepSessionId 必须是当前仍活跃且归属该账号的会话；归属不匹配（属于别人或不存在）时
     * 不下线任何会话，作为防误伤的防御性校验。名额立即释放。
     */
    public int revokeOthers(String username, String keepSessionId) {
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            Set<String> ids = idsByUser.get(username);
            if (ids == null || ids.isEmpty()) {
                return 0;
            }
            SessionRecord keep = keepSessionId == null ? null : byId.get(keepSessionId);
            if (keep == null || !username.equals(keep.username())) {
                log.info("revoke others skipped: username={}, keep={} not an own active session",
                        username, keepSessionId);
                return 0;
            }
            int n = 0;
            for (String id : new ArrayList<>(ids)) {
                if (!id.equals(keepSessionId)
                        && terminateLocked(ids, id, TerminationReason.LOGOUT) != null) {
                    n++;
                }
            }
            log.info("revoke others: username={}, keep={}, revoked={}", username, keepSessionId, n);
            return n;
        } finally {
            lock.unlock();
        }
    }

    /**
     * 定向下线：仅当目标会话当前活跃且归属 ownerUsername 时终止（原因 LOGOUT）。
     * 归属不匹配/不存在/已终止返回 false，由上层映射为与"资源不存在"一致的结论，
     * 不泄露目标会话是否存在、属于谁。
     */
    public boolean revokeOwned(String ownerUsername, String targetSessionId) {
        if (ownerUsername == null || targetSessionId == null) {
            return false;
        }
        SessionRecord record = byId.get(targetSessionId);
        if (record == null || !ownerUsername.equals(record.username())) {
            return false;
        }
        ReentrantLock lock = lockFor(ownerUsername);
        lock.lock();
        try {
            SessionRecord still = byId.get(targetSessionId);
            if (still == null || !ownerUsername.equals(still.username())) {
                return false;
            }
            Instant now = Instant.now();
            if (still.isExpired(now)) {
                terminateLocked(idsByUser.get(ownerUsername), targetSessionId, TerminationReason.EXPIRED);
                return false;
            }
            return terminateLocked(idsByUser.get(ownerUsername), targetSessionId, TerminationReason.LOGOUT) != null;
        } finally {
            lock.unlock();
        }
    }

    /**
     * 列出某账号当前活跃会话视图，稳定排序（createdAt 升序、id 兜底），
     * 结果只包含该账号自己的会话，其他账号的活动无法被感知。
     * 过期会话在列出时惰性转为 EXPIRED 墓碑，不出现在列表中。
     */
    public List<SessionView> listActive(String username, String currentSessionId) {
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            Set<String> ids = idsByUser.get(username);
            if (ids == null || ids.isEmpty()) {
                return List.of();
            }
            evictExpiredLocked(ids);
            List<SessionView> views = new ArrayList<>(ids.size());
            for (String id : ids) {
                SessionRecord r = byId.get(id);
                if (r != null) {
                    views.add(SessionView.of(r, id.equals(currentSessionId)));
                }
            }
            views.sort(Comparator.comparing(SessionView::createdAt).thenComparing(SessionView::id));
            return views;
        } finally {
            lock.unlock();
        }
    }

    /** 更新某会话的最近活动时间，仅对活跃且未过期的会话生效。 */
    public void touch(String sessionId, Instant now) {
        SessionRecord record = byId.get(sessionId);
        if (record == null) {
            return;
        }
        record.touch(now);
    }

    /**
     * 滑动续期：会话存在、未终止且未过期才续期，保证终止/过期状态不可被续期复活。
     * 续期成功时同时刷新最近活动时间。
     *
     * @return 查找终态；ACTIVE 表示续期成功，TERMINATED 携带真实原因（EXPIRED/LOGOUT/CAP_EVICTED），
     *         UNKNOWN 表示不存在/伪造
     */
    public SessionLookup renew(String sessionId, long ttlSeconds) {
        SessionLookup lookup = lookup(sessionId);
        if (lookup.state() != SessionLookup.State.ACTIVE) {
            return lookup;
        }
        SessionRecord record = lookup.record();
        ReentrantLock lock = lockFor(record.username());
        lock.lock();
        try {
            Instant now = Instant.now();
            if (byId.get(sessionId) != record || record.isExpired(now)) {
                // 并发下刚被终止或过期：返回最新结论。
                return lookup(sessionId);
            }
            if (!record.extend(now.plusSeconds(ttlSeconds))) {
                return lookup(sessionId);
            }
            record.touch(now);
            return SessionLookup.active(record);
        } finally {
            lock.unlock();
        }
    }

    public int activeCount(String username) {
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            Set<String> ids = idsByUser.get(username);
            if (ids == null) {
                return 0;
            }
            evictExpiredLocked(ids);
            return ids.size();
        } finally {
            lock.unlock();
        }
    }

    private void evictExpiredLocked(Set<String> ids) {
        if (ids == null) {
            return;
        }
        Instant now = Instant.now();
        ids.removeIf(id -> {
            SessionRecord r = byId.get(id);
            if (r == null) {
                return true;
            }
            if (r.isExpired(now)) {
                terminateRecord(r, TerminationReason.EXPIRED, now);
                byId.remove(id, r);
                tombstones.put(id, r);
                return true;
            }
            return false;
        });
    }

    /** 在账号锁内完成终止：活跃表 → 墓碑表，名额（ids）立即释放。返回被终止的记录，失败返回 null。 */
    private SessionRecord terminateLocked(Set<String> ids, String sessionId, TerminationReason reason) {
        SessionRecord r = byId.remove(sessionId);
        if (r == null) {
            return null;
        }
        terminateRecord(r, reason, Instant.now());
        if (ids != null) {
            ids.remove(sessionId);
        }
        tombstones.put(sessionId, r);
        sweepTombstonesIfNeeded();
        return r;
    }

    private void terminateRecord(SessionRecord r, TerminationReason reason, Instant now) {
        boolean first = r.terminate(reason, now);
        if (!first) {
            log.info("termination reason preserved: sessionId={}, reason={}", r.id(), r.terminationReason());
        }
    }

    private void sweepTombstonesIfNeeded() {
        if (tombstones.size() < TOMBSTONE_SWEEP_THRESHOLD) {
            return;
        }
        Instant cutoff = Instant.now().minusSeconds(TOMBSTONE_TTL_SECONDS);
        tombstones.entrySet().removeIf(e -> {
            Instant at = e.getValue().terminatedAt();
            return at != null && at.isBefore(cutoff);
        });
    }
}
