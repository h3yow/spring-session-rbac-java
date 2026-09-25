package com.github.h3yow.springsessionrbacjava.session;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 并发安全的内存会话存储。
 * <ul>
 *   <li>同账号并发会话上限可配置，超出时按稳定策略淘汰该账号最旧的会话；</li>
 *   <li>按用户名加锁，保证并发登录/注销/续期不产生串号或不可恢复状态；</li>
 *   <li>会话 ID 与 CSRF 令牌由 CSPRNG 生成，每次登录签发全新 ID（防会话固定）。</li>
 * </ul>
 */
@Component
public class SessionStore {

    private final ConcurrentHashMap<String, SessionRecord> byId = new ConcurrentHashMap<>();
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
     * 创建会话。若该账号已达并发上限，淘汰其最旧会话（稳定策略），再插入新会话。
     */
    public SessionRecord create(String username, long ttlSeconds, int maxConcurrentSessions) {
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            Set<String> ids = idsByUser.computeIfAbsent(username, u -> new HashSet<>());
            evictExpiredLocked(ids);
            while (ids.size() >= maxConcurrentSessions) {
                String oldest = ids.stream()
                        .map(byId::get)
                        .filter(r -> r != null)
                        .min(Comparator.comparing(SessionRecord::createdAt))
                        .map(SessionRecord::id)
                        .orElse(null);
                if (oldest == null) {
                    break;
                }
                removeLocked(ids, oldest);
            }
            SessionRecord record = new SessionRecord(newToken(), username, newToken(),
                    Instant.now(), Instant.now().plusSeconds(ttlSeconds));
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

    /** 注销，幂等：已不存在的会话返回 false，重复注销不报错。 */
    public boolean revoke(String sessionId) {
        SessionRecord record = byId.get(sessionId);
        if (record == null) {
            return false;
        }
        ReentrantLock lock = lockFor(record.username());
        lock.lock();
        try {
            record.revoke();
            Set<String> ids = idsByUser.get(record.username());
            if (ids != null) {
                ids.remove(sessionId);
            }
            byId.remove(sessionId);
            return true;
        } finally {
            lock.unlock();
        }
    }

    public int revokeAll(String username) {
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            Set<String> ids = idsByUser.getOrDefault(username, Set.of());
            int n = 0;
            for (String id : new ArrayList<>(ids)) {
                SessionRecord r = byId.remove(id);
                if (r != null) {
                    r.revoke();
                    n++;
                }
            }
            ids.clear();
            return n;
        } finally {
            lock.unlock();
        }
    }

    /** 滑动续期：会话存在、未注销且未过期才续期，保证过期/注销状态不可被续期复活。 */
    public boolean renew(String sessionId, long ttlSeconds) {
        SessionRecord record = byId.get(sessionId);
        if (record == null) {
            return false;
        }
        ReentrantLock lock = lockFor(record.username());
        lock.lock();
        try {
            if (byId.get(sessionId) != record || record.isRevoked() || record.isExpired(Instant.now())) {
                return false;
            }
            return record.extend(Instant.now().plusSeconds(ttlSeconds));
        } finally {
            lock.unlock();
        }
    }

    public int activeCount(String username) {
        ReentrantLock lock = lockFor(username);
        lock.lock();
        try {
            Set<String> ids = idsByUser.getOrDefault(username, Set.of());
            evictExpiredLocked(ids);
            return ids.size();
        } finally {
            lock.unlock();
        }
    }

    private void evictExpiredLocked(Set<String> ids) {
        Instant now = Instant.now();
        ids.removeIf(id -> {
            SessionRecord r = byId.get(id);
            if (r == null || r.isExpired(now)) {
                byId.remove(id);
                return true;
            }
            return false;
        });
    }

    private void removeLocked(Set<String> ids, String sessionId) {
        SessionRecord r = byId.remove(sessionId);
        if (r != null) {
            r.revoke();
        }
        ids.remove(sessionId);
    }
}
