package com.github.h3yow.springsessionrbacjava.security;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * 会话管理：创建（含并发上限与稳定淘汰）、校验、滑动续期、注销。
 * 失效原因可区分：未知 id、已注销、已过期分别返回不同原因。
 */
@Component
public class SessionManager {

    private final SecurityProperties properties;
    private final Map<String, SessionRecord> sessions = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private Clock clock = Clock.systemUTC();

    public SessionManager(SecurityProperties properties) {
        this.properties = properties;
    }

    /** 测试用：注入可控时钟。 */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    /**
     * 创建会话。同一账号超过并发上限时，按稳定策略淘汰创建时间最早的活跃会话。
     * 整体加锁保证并发登录下上限不被突破、不产生串号。
     */
    public synchronized SessionRecord createSession(String username) {
        Instant now = clock.instant();
        List<SessionRecord> activeOfUser = new ArrayList<>();
        for (SessionRecord r : sessions.values()) {
            if (r.getUsername().equals(username) && !r.isRevoked() && !r.isExpired(now)) {
                activeOfUser.add(r);
            }
        }
        activeOfUser.sort(Comparator.comparing(SessionRecord::getCreatedAt)
                .thenComparing(SessionRecord::getId));
        while (activeOfUser.size() >= properties.getMaxConcurrentSessions()) {
            SessionRecord evicted = activeOfUser.remove(0);
            evicted.revoke();
        }
        SessionRecord record = new SessionRecord(newToken(), username, newToken(),
                now, now.plus(properties.getSessionTtl()));
        sessions.put(record.getId(), record);
        return record;
    }

    /**
     * 校验会话并滑动续期；失败抛出携带可区分原因的 AuthException。
     */
    public SessionRecord validateAndRenew(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new AuthException(AuthFailureReason.SESSION_MISSING);
        }
        SessionRecord record = sessions.get(sessionId);
        if (record == null) {
            throw new AuthException(AuthFailureReason.SESSION_INVALID);
        }
        if (record.isRevoked()) {
            throw new AuthException(AuthFailureReason.SESSION_REVOKED);
        }
        Instant now = clock.instant();
        if (record.isExpired(now)) {
            throw new AuthException(AuthFailureReason.SESSION_EXPIRED);
        }
        // 滑动续期
        record.setExpiresAt(now.plus(properties.getSessionTtl()));
        return record;
    }

    /**
     * 注销：标记 revoked（保留记录以区分“已注销”与“未知 id”）。幂等。
     */
    public void invalidate(String sessionId) {
        if (sessionId == null) {
            return;
        }
        SessionRecord record = sessions.get(sessionId);
        if (record != null) {
            record.revoke();
        }
    }

    private String newToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
