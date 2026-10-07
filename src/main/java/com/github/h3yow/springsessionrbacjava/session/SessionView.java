package com.github.h3yow.springsessionrbacjava.session;

import java.time.Instant;

/**
 * 会话列表中的单个会话视图。仅包含当前用户自己的活跃会话；
 * 字段稳定、按 createdAt 升序（id 兜底）排列，不受其他账号活动影响。
 *
 * @param id           会话 ID（用户下线指定会话时回传）
 * @param createdAt    会话建立时间（登录时刻）
 * @param lastActivityAt 最近一次活动时间（受保护资源访问/续期）
 * @param current      是否为发起本次列表请求的会话
 */
public record SessionView(String id, Instant createdAt, Instant lastActivityAt, boolean current) {

    public static SessionView of(SessionRecord record, boolean current) {
        return new SessionView(record.id(), record.createdAt(), record.lastActivityAt(), current);
    }
}
