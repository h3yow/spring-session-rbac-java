package com.github.h3yow.springsessionrbacjava.security;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 可配置的安全参数：会话 TTL、并发会话上限、Cookie 与 CSRF 设置。
 */
@Component
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

    private Duration sessionTtl = Duration.ofMinutes(30);
    private int maxConcurrentSessions = 2;
    private String cookieName = "SESSION";
    private boolean cookieSecure = false;
    private String csrfHeaderName = "X-CSRF-TOKEN";

    public Duration getSessionTtl() {
        return sessionTtl;
    }

    public void setSessionTtl(Duration sessionTtl) {
        this.sessionTtl = sessionTtl;
    }

    public int getMaxConcurrentSessions() {
        return maxConcurrentSessions;
    }

    public void setMaxConcurrentSessions(int maxConcurrentSessions) {
        this.maxConcurrentSessions = maxConcurrentSessions;
    }

    public String getCookieName() {
        return cookieName;
    }

    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    public boolean isCookieSecure() {
        return cookieSecure;
    }

    public void setCookieSecure(boolean cookieSecure) {
        this.cookieSecure = cookieSecure;
    }

    public String getCsrfHeaderName() {
        return csrfHeaderName;
    }

    public void setCsrfHeaderName(String csrfHeaderName) {
        this.csrfHeaderName = csrfHeaderName;
    }
}
