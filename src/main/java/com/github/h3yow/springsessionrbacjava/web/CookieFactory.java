package com.github.h3yow.springsessionrbacjava.web;

import com.github.h3yow.springsessionrbacjava.config.SecurityProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

/**
 * 构造带安全属性的会话 Cookie：HttpOnly、SameSite=Strict、Path=/，Secure 可配置。
 */
@Component
public class CookieFactory {

    public static final String SESSION_COOKIE = "SESSIONID";

    private final SecurityProperties properties;

    public CookieFactory(SecurityProperties properties) {
        this.properties = properties;
    }

    public String sessionCookie(String sessionId, long maxAgeSeconds) {
        return ResponseCookie.from(SESSION_COOKIE, sessionId)
                .httpOnly(true)
                .secure(properties.isCookieSecure())
                .sameSite("Strict")
                .path("/")
                .maxAge(maxAgeSeconds)
                .build()
                .toString();
    }

    public String clearSessionCookie() {
        return ResponseCookie.from(SESSION_COOKIE, "")
                .httpOnly(true)
                .secure(properties.isCookieSecure())
                .sameSite("Strict")
                .path("/")
                .maxAge(0)
                .build()
                .toString();
    }
}
