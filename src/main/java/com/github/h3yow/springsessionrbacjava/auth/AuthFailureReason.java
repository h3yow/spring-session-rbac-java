package com.github.h3yow.springsessionrbacjava.auth;

/**
 * 可区分的失败原因。对外响应只暴露不泄露账号存在性的子集。
 */
public enum AuthFailureReason {
    NONE,
    INVALID_CREDENTIALS,
    SESSION_MISSING,
    SESSION_EXPIRED,
    SESSION_REVOKED,
    SESSION_CAP_EVICTED,
    CSRF_TOKEN_MISSING,
    CSRF_TOKEN_MISMATCH,
    FORBIDDEN
}
