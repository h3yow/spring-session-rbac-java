package com.github.h3yow.springsessionrbacjava.auth;

/**
 * 登录/会话解析结果。失败时 reason 可区分，但对外映射时统一为 INVALID_CREDENTIALS。
 */
public record AuthResult(boolean success, String sessionId, String csrfToken,
                         AuthFailureReason reason) {
    public static AuthResult ok(String sessionId, String csrfToken) {
        return new AuthResult(true, sessionId, csrfToken, AuthFailureReason.NONE);
    }

    public static AuthResult fail(AuthFailureReason reason) {
        return new AuthResult(false, null, null, reason);
    }
}
