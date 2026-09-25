package com.github.h3yow.springsessionrbacjava.session;

import java.time.Instant;

/**
 * 服务端会话记录。角色不快照在会话里，授权时实时查询，保证策略变更即时生效。
 * 字段通过 synchronized 方法保护，保证并发下续期/注销/读取的一致性。
 */
public class SessionRecord {

    private final String id;
    private final String username;
    private final String csrfToken;
    private final Instant createdAt;
    private volatile Instant expiresAt;
    private volatile boolean revoked;

    public SessionRecord(String id, String username, String csrfToken, Instant createdAt, Instant expiresAt) {
        this.id = id;
        this.username = username;
        this.csrfToken = csrfToken;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.revoked = false;
    }

    public String id() { return id; }

    public String username() { return username; }

    public String csrfToken() { return csrfToken; }

    public Instant createdAt() { return createdAt; }

    public Instant expiresAt() { return expiresAt; }

    public boolean isRevoked() { return revoked; }

    public boolean isExpired(Instant now) { return !now.isBefore(expiresAt); }

    public void revoke() { this.revoked = true; }

    /** 滑动续期：仅在未注销时生效，返回是否续期成功。 */
    public synchronized boolean extend(Instant newExpiry) {
        if (revoked) {
            return false;
        }
        this.expiresAt = newExpiry;
        return true;
    }
}
