package com.github.h3yow.springsessionrbacjava.session;

import java.time.Instant;

/**
 * 会话列表项（仅包含当前用户自己的活跃会话）。
 * 字段集合与排序由 SessionStore 保证稳定，不受其他账号活动影响。
 */
public record SessionView(String sessionId,
                          Instant createdAt,
                          Instant lastAccessAt,
                          Instant expiresAt,
                          boolean current) {
}
