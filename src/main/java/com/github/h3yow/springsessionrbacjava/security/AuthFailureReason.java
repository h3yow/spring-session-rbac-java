package com.github.h3yow.springsessionrbacjava.security;

/**
 * 可区分的认证/授权失败原因。对外响应使用稳定错误码。
 */
public enum AuthFailureReason {
    INVALID_CREDENTIALS,
    SESSION_MISSING,
    SESSION_INVALID,
    SESSION_EXPIRED,
    SESSION_REVOKED,
    CSRF_TOKEN_MISSING,
    CSRF_TOKEN_MISMATCH,
    AUTHENTICATION_REQUIRED,
    RESOURCE_NOT_AVAILABLE
}
