package com.github.h3yow.springsessionrbacjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 安全相关可配置项。
 */
@Component
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    private long sessionTtlSeconds = 1800;
    private int maxConcurrentSessions = 2;
    private boolean cookieSecure = false;

    public long getSessionTtlSeconds() { return sessionTtlSeconds; }
    public void setSessionTtlSeconds(long v) { this.sessionTtlSeconds = v; }
    public int getMaxConcurrentSessions() { return maxConcurrentSessions; }
    public void setMaxConcurrentSessions(int v) { this.maxConcurrentSessions = v; }
    public boolean isCookieSecure() { return cookieSecure; }
    public void setCookieSecure(boolean v) { this.cookieSecure = v; }
}
