package com.github.h3yow.springsessionrbacjava.session;

/**
 * 会话查找结果：状态机三态，终态携带终止原因。
 * <ul>
 *   <li>{@link State#ACTIVE}：会话存在且未过期，record 非空；</li>
 *   <li>{@link State#TERMINATED}：会话曾存在，record 非空且携带 {@link TerminationReason}；</li>
 *   <li>{@link State#UNKNOWN}：不存在/伪造，record 为空，不携带任何额外信息。</li>
 * </ul>
 */
public record SessionLookup(State state, SessionRecord record, TerminationReason reason) {

    public enum State {
        ACTIVE,
        TERMINATED,
        UNKNOWN
    }

    public static SessionLookup active(SessionRecord record) {
        return new SessionLookup(State.ACTIVE, record, null);
    }

    public static SessionLookup terminated(SessionRecord record, TerminationReason reason) {
        return new SessionLookup(State.TERMINATED, record, reason);
    }

    public static SessionLookup unknown() {
        return new SessionLookup(State.UNKNOWN, null, null);
    }
}
