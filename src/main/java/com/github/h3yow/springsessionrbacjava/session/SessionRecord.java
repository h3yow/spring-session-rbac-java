package com.github.h3yow.springsessionrbacjava.session;

import java.time.Instant;

/**
 * 服务端会话记录。角色不快照在会话里，授权时实时查询，保证策略变更即时生效。
 * 字段通过 synchronized 方法保护，保证并发下续期/注销/终止/读取的一致性。
 * 终止是一次性、不可恢复的终态：原因由首次终止者确定（注销/上限挤掉/自然过期），
 * 终止后不可被续期复活。
 */
public class SessionRecord {

    private final String id;
    private final String username;
    private final String csrfToken;
    private final Instant createdAt;
    private volatile Instant expiresAt;
    private volatile Instant lastActivityAt;
    private volatile boolean terminated;
    private volatile TerminationReason terminationReason;
    private volatile Instant terminatedAt;

    public SessionRecord(String id, String username, String csrfToken, Instant createdAt, Instant expiresAt) {
        this.id = id;
        this.username = username;
        this.csrfToken = csrfToken;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.lastActivityAt = createdAt;
        this.terminated = false;
        this.terminationReason = null;
        this.terminatedAt = null;
    }

    public String id() { return id; }

    public String username() { return username; }

    public String csrfToken() { return csrfToken; }

    public Instant createdAt() { return createdAt; }

    public Instant expiresAt() { return expiresAt; }

    public Instant lastActivityAt() { return lastActivityAt; }

    public boolean isTerminated() { return terminated; }

    public TerminationReason terminationReason() { return terminationReason; }

    public Instant terminatedAt() { return terminatedAt; }

    public boolean isExpired(Instant now) { return !now.isBefore(expiresAt); }

    /**
     * 将会话置为终态。仅当此前未终止时生效，首次终止原因被保留——
     * 保证并发下"注销"与"判定过期"不会互相覆盖结论。
     *
     * @return 是否由本次调用完成终止；已终止返回 false（保留原原因）
     */
    public synchronized boolean terminate(TerminationReason reason, Instant at) {
        if (terminated) {
            return false;
        }
        this.terminated = true;
        this.terminationReason = reason;
        this.terminatedAt = at;
        return true;
    }

    /** 更新最近活动时间。仅存活会话可更新，终态保持不变。 */
    public synchronized void touch(Instant at) {
        if (!terminated && at.isAfter(lastActivityAt)) {
            this.lastActivityAt = at;
        }
    }

    /** 滑动续期：仅在未终止时生效，返回是否续期成功。 */
    public synchronized boolean extend(Instant newExpiry) {
        if (terminated) {
            return false;
        }
        this.expiresAt = newExpiry;
        return true;
    }
}
