package com.github.h3yow.springsessionrbacjava.session;

/**
 * 会话失效的可区分原因（仅对持有真实会话 ID 的本人可分辨）。
 * <ul>
 *   <li>{@link #NONE}：会话仍活跃；</li>
 *   <li>{@link #SELF_LOGOUT}：本人用该会话自己调用注销；</li>
 *   <li>{@link #USER_TERMINATED}：账号持有人在会话管理中主动下线（可能从另一个会话发起）；</li>
 *   <li>{@link #CAP_EVICTED}：超过并发上限，被新登录按稳定策略挤掉。</li>
 * </ul>
 * 自然过期不使用本枚举，由 expiresAt 判定为 SESSION_EXPIRED。
 */
public enum RevocationReason {
    NONE,
    SELF_LOGOUT,
    USER_TERMINATED,
    CAP_EVICTED
}
