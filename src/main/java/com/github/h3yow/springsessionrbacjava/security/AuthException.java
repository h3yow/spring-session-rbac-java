package com.github.h3yow.springsessionrbacjava.security;

/**
 * 携带稳定失败原因的安全异常。
 */
public class AuthException extends RuntimeException {

    private final AuthFailureReason reason;

    public AuthException(AuthFailureReason reason) {
        super(reason.name());
        this.reason = reason;
    }

    public AuthFailureReason getReason() {
        return reason;
    }
}
