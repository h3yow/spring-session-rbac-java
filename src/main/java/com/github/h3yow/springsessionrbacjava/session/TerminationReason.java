package com.github.h3yow.springsessionrbacjava.session;

/**
 * 会话终止原因（服务端可区分，仅对持有该会话 ID 的本人可见）：
 * <ul>
 *   <li>{@link #LOGOUT}：本人主动注销或通过会话管理定向下线；</li>
 *   <li>{@link #CAP_EVICTED}：同账号登录数达到并发上限，被新登录按最旧优先策略挤掉；</li>
 *   <li>{@link #EXPIRED}：TTL 自然到期。</li>
 * </ul>
 * 不存在/伪造的会话不会得到任何原因（由调用方映射为 SESSION_MISSING），
 * 因此该枚举不会泄露账号或会话的存在性。
 */
public enum TerminationReason {
    LOGOUT,
    CAP_EVICTED,
    EXPIRED
}
