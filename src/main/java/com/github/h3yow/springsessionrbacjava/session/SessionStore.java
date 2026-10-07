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
 *   <li>同账号并发会话上限可配置，超出时按稳定策略淘汰该账号最旧的<b>活跃</b>会话，
 *       被挤掉的会话转为带 {@link RevocationReason#CAP_EVICTED} 原因的墓碑并立即释放名额；</li>
 *   <li>注销/管理下线同样转为墓碑（保留 tombstoneTtlSeconds），
 *       使本人在保留期内能分辨"自己注销 / 被主动下线 / 被挤掉"，保留期后惰性清除，
 *       清除后与从未存在过的伪造 ID 无法区分（SESSION_MISSING）；</li>
 *   <li>按用户名加锁，保证并发登录/下线/续期/列表读取不串号、不错杀他人会话；</li>
 *   <li>会话 ID 与 CSRF 令牌由 CSPRNG 生成，每次登录签发全新 ID（防会话固定）。</li>
 * </ul>
 */
@Component
public class SessionStore {

    private static final Logger log = LoggerFactory.getLogger(SessionStore.class);

    /** 墓碑（含已过期记录）默认保留时长：期间本人可分辨失效原因。 */
    public static final long DEFAULT_TOMBSTONE_TTL_SECONDS = 86_400L;

    /** revokeIfOwner 的结果。 */
    public enum OwnedRevokeResult {
        REVOKED,
        NOT_FOUND
    }

    private final ConcurrentHashMap<String, SessionRecord> byId = new ConcurrentHashMap<>();
    /** 用户名下全部"仍被保留"的会话 id：活跃 + 墓碑（过期未超保留宽限的也算保留）。 */
    private final ConcurrentHashMap<String, Set<String>> idsByUser = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ReentrantLock> userLocks = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    private volatile long tombstoneTtlSeconds = DEFAULT_TOMBSTONE_TTL_SECONDS;

    public void setTombstoneTtlSeconds(long v) {
        this.tombstoneTtlSeconds = v;
    }

    private String newToken() {
        byte[] buf = new byte[32];
        random.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private ReentrantLock lockFor(String username) {
        return userLocks.computeIfAbsent(username, u -> new ReentrantLock());
    }

    private static boolean isActive(SessionRecord r, Instant now) {
        return !r.isRevoked() && !r.isExpired(now);
    }

    /**
     * 创建会话。若该账号活跃会话已达上限，淘汰最旧的活跃会话（稳定策略，标记 CAP_EVICTED），
     * 被淘汰会话立即释放名额但保留为墓碑，再插入新会话。
     */
    public SessionRecord create(String username, long ttlSeconds, int maxConcurrentSessions) {
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            Set<String> ids = idsByUser.computeIfAbsent(username, u -> ConcurrentHashMap.newKeySet());
            Instant now = Instant.now();
            sweepLocked(ids, now);
            while (activeCountLocked(ids, now) >= maxConcurrentSessions) {
                String oldest = ids.stream()
                        .map(byId::get)
                        .filter(r -> r != null && isActive(r, now))
                        .min(Comparator.comparing(SessionRecord::createdAt).thenComparing(SessionRecord::id))
                        .map(SessionRecord::id)
                        .orElse(null);
                if (oldest == null) {
                    break;
                }
                SessionRecord evicted = byId.get(oldest);
                evicted.markRevoked(RevocationReason.CAP_EVICTED, now.plusSeconds(tombstoneTtlSeconds));
                log.info("cap eviction: username={}, evictedSessionId={}, cap={}",
                        username, oldest, maxConcurrentSessions);
            }
            SessionRecord record = new SessionRecord(newToken(), username, newToken(),
                    now, now.plusSeconds(ttlSeconds));
            byId.put(record.id(), record);
            ids.add(record.id());
            return record;
        } finally {
            lock.unlock();
        }
    }

    public Optional<SessionRecord> find(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byId.get(sessionId));
    }

    /** 本人注销：幂等。活跃会话转为 SELF_LOGOUT 墓碑并立即释放名额；已是墓碑/不存在返回 false。 */
    public boolean revoke(String sessionId) {
        return revoke(sessionId, RevocationReason.SELF_LOGOUT);
    }

    /**
     * 按指定原因下线会话，幂等：仅当前活跃（含已过期但尚未清除）的记录会被转为墓碑；
     * 已下线的记录保留第一次的原因并返回 false，不存在返回 false。
     */
    public boolean revoke(String sessionId, RevocationReason reason) {
        SessionRecord record = byId.get(sessionId);
        if (record == null) {
            return false;
        }
        ReentrantLock lock = lockFor(record.username());
        lock.lock();
        try {
            SessionRecord current = byId.get(sessionId);
            if (current == null || current.isRevoked()) {
                return false;
            }
            Instant now = Instant.now();
            current.markRevoked(reason, now.plusSeconds(tombstoneTtlSeconds));
            log.info("session revoked: username={}, sessionId={}, reason={}",
                    current.username(), sessionId, reason);
            return true;
        } finally {
            lock.unlock();
        }
    }

    public int revokeAll(String username) {
        return revokeAll(username, RevocationReason.USER_TERMINATED);
    }

    /** 下线该用户全部未下线会话（墓碑保留第一次原因），返回实际新下线数量。 */
    public int revokeAll(String username, RevocationReason reason) {
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            Set<String> ids = idsByUser.get(username);
            if (ids == null) {
                return 0;
            }
            Instant now = Instant.now();
            int n = 0;
            for (String id : new ArrayList<>(ids)) {
                SessionRecord r = byId.get(id);
                if (r != null && !r.isRevoked()) {
                    r.markRevoked(reason, now.plusSeconds(tombstoneTtlSeconds));
                    n++;
                }
            }
            log.info("revoke all: username={}, reason={}, newlyRevoked={}", username, reason, n);
            return n;
        } finally {
            lock.unlock();
        }
    }

    /** 滑动续期：会话存在、未下线且未过期才续期，保证过期/下线状态不可被续期复活。 */
    public boolean renew(String sessionId, long ttlSeconds) {
        SessionRecord record = byId.get(sessionId);
        if (record == null) {
            return false;
        }
        ReentrantLock lock = lockFor(record.username());
        lock.lock();
        try {
            SessionRecord current = byId.get(sessionId);
            if (current != record || current.isRevoked() || current.isExpired(Instant.now())) {
                return false;
            }
            return current.extend(Instant.now().plusSeconds(ttlSeconds));
        } finally {
            lock.unlock();
        }
    }

    /** 记录一次已认证活动；仅在记录仍活跃时更新最近活动时间，无锁快速路径。 */
    public void touch(String sessionId) {
        SessionRecord record = byId.get(sessionId);
        if (record != null) {
            record.touch(Instant.now());
        }
    }

    /** 下线目标会话，且目标必须属于该用户；归属判定与下线在同一把用户锁内完成，杜绝并发下张冠李戴。 */
    public OwnedRevokeResult revokeIfOwner(String username, String targetSessionId, RevocationReason reason) {
        SessionRecord record = byId.get(targetSessionId);
        if (record == null || !record.username().equals(username)) {
            // 不存在与"属于别人"合并为同一结果，调用方给出逐字节一致的 404。
            return OwnedRevokeResult.NOT_FOUND;
        }
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            SessionRecord current = byId.get(targetSessionId);
            if (current == null || !current.username().equals(username)) {
                return OwnedRevokeResult.NOT_FOUND;
            }
            if (current.isRevoked()) {
                // 幂等：本人重复下线自己已在墓碑中的会话，视为成功且保留首次原因。
                return OwnedRevokeResult.REVOKED;
            }
            current.markRevoked(reason, Instant.now().plusSeconds(tombstoneTtlSeconds));
            log.info("session revoked: username={}, sessionId={}, reason={}",
                    username, targetSessionId, reason);
            return OwnedRevokeResult.REVOKED;
        } finally {
            lock.unlock();
        }
    }

    /** 在同一把用户锁内下线除 keepSessionId 外的全部未下线会话，返回新下线数量。 */
    public int revokeOthers(String username, String keepSessionId, RevocationReason reason) {
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            Set<String> ids = idsByUser.get(username);
            if (ids == null) {
                return 0;
            }
            Instant now = Instant.now();
            int n = 0;
            for (String id : new ArrayList<>(ids)) {
                if (id.equals(keepSessionId)) {
                    continue;
                }
                SessionRecord r = byId.get(id);
                if (r != null && !r.isRevoked()) {
                    r.markRevoked(reason, now.plusSeconds(tombstoneTtlSeconds));
                    n++;
                }
            }
            log.info("revoke others: username={}, keep={}, reason={}, newlyRevoked={}",
                    username, keepSessionId, reason, n);
            return n;
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
            Instant now = Instant.now();
            sweepLocked(ids, now);
            return activeCountLocked(ids, now);
        } finally {
            lock.unlock();
        }
    }

    /**
     * 列出该用户全部活跃会话。排序稳定：按创建时间升序，创建时间相同再按会话 ID 升序；
     * 结果只包含本人会话，不受其他账号登录/下线影响。
     */
    public List<SessionRecord> listActive(String username) {
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            Set<String> ids = idsByUser.get(username);
            if (ids == null) {
                return List.of();
            }
            Instant now = Instant.now();
            sweepLocked(ids, now);
            return ids.stream()
                    .map(byId::get)
                    .filter(r -> r != null && isActive(r, now))
                    .sorted(Comparator.comparing(SessionRecord::createdAt).thenComparing(SessionRecord::id))
                    .toList();
        } finally {
            lock.unlock();
        }
    }

    private int activeCountLocked(Set<String> ids, Instant now) {
        int n = 0;
        for (String id : ids) {
            SessionRecord r = byId.get(id);
            if (r != null && isActive(r, now)) {
                n++;
            }
        }
        return n;
    }

    /**
     * 惰性清除：墓碑超过保留截止时间、或非墓碑记录过期超过一个保留宽限，则彻底删除；
     * 删除后该 ID 对外即为 SESSION_MISSING，与伪造 ID 不可区分。
     */
    private void sweepLocked(Set<String> ids, Instant now) {
        ids.removeIf(id -> {
            SessionRecord r = byId.get(id);
            if (r == null) {
                return true;
            }
            boolean due;
            if (r.isRevoked()) {
                due = r.isPurgeDue(now);
            } else if (r.isExpired(now)) {
                due = !now.isBefore(r.expiresAt().plusSeconds(tombstoneTtlSeconds));
            } else {
                due = false;
            }
            if (due) {
                byId.remove(id); // 主表与用户索引一起清除，之后 find 即为空（与伪造 ID 不可区分）
            }
            return due;
        });
    }
}
