package com.github.h3yow.springsessionrbacjava.session;

import java.time.Instant;

/**
 * 服务端会话记录。角色不快照在会话里，授权时实时查询，保证策略变更即时生效。
 * <p>
 * 会话被下线后不会立即从存储删除，而是转为"墓碑"（revoked=true 且带 RevocationReason），
 * 保留到 purgeAt，使持有真实会话 ID 的本人能在一段时间内分辨"为什么被登出"；
 * 墓碑保留期结束后惰性清除，之后该 ID 与从未存在过的伪造 ID 一样按 MISSING 处理。
 * 字段通过 synchronized 方法保护，保证并发下续期/下线/读取的一致性。
 */
public class SessionRecord {

    private final String id;
    private final String username;
    private final String csrfToken;
    private final Instant createdAt;
    private volatile Instant expiresAt;
    private volatile Instant lastAccessAt;
    private volatile boolean revoked;
    private volatile RevocationReason revocationReason = RevocationReason.NONE;
    private volatile Instant purgeAt;

    public SessionRecord(String id, String username, String csrfToken, Instant createdAt, Instant expiresAt) {
        this.id = id;
        this.username = username;
        this.csrfToken = csrfToken;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.lastAccessAt = createdAt;
        this.purgeAt = Instant.MAX;
    }

    public String id() { return id; }

    public String username() { return username; }

    public String csrfToken() { return csrfToken; }

    public Instant createdAt() { return createdAt; }

    public Instant expiresAt() { return expiresAt; }

    public Instant lastAccessAt() { return lastAccessAt; }

    public boolean isRevoked() { return revoked; }

    public RevocationReason revocationReason() { return revocationReason; }

    public Instant purgeAt() { return purgeAt; }

    public boolean isExpired(Instant now) { return !now.isBefore(expiresAt); }

    /** 墓碑保留期是否已结束（结束后应从存储清除，对外回到 MISSING）。 */
    public boolean isPurgeDue(Instant now) { return !now.isBefore(purgeAt); }

    /** 记录最近一次已认证活动（仅活跃会话更新）。 */
    public synchronized void touch(Instant at) {
        if (!revoked) {
            this.lastAccessAt = at;
        }
    }

    /**
     * 标记下线并转为墓碑。幂等：重复调用保留第一次的原因，不覆盖。
     */
    public synchronized void markRevoked(RevocationReason reason, Instant purgeAt) {
        if (!revoked) {
            this.revoked = true;
            this.revocationReason = reason;
            this.purgeAt = purgeAt;
        }
    }

    /** 兼容旧调用：不带原因的下线按本人主动注销处理。 */
    public void revoke() {
        markRevoked(RevocationReason.SELF_LOGOUT, Instant.MAX);
    }

    /** 滑动续期：仅在未注销时生效，返回是否续期成功。 */
    public synchronized boolean extend(Instant newExpiry) {
        if (revoked) {
            return false;
        }
        this.expiresAt = newExpiry;
        return true;
    }
}
