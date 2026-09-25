package com.github.h3yow.springsessionrbacjava.security;

import java.time.Instant;

/**
 * 服务端会话记录。只保存用户名，角色在请求时实时判定。
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
    }

    public String getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getCsrfToken() {
        return csrfToken;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void revoke() {
        this.revoked = true;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }
}
