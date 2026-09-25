package com.github.h3yow.springsessionrbacjava.security.web;

import java.io.IOException;

import com.github.h3yow.springsessionrbacjava.security.AuthException;
import com.github.h3yow.springsessionrbacjava.security.SessionManager;
import com.github.h3yow.springsessionrbacjava.security.SessionRecord;
import com.github.h3yow.springsessionrbacjava.security.SecurityProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 会话解析过滤器：从 Cookie 解析会话、校验并滑动续期。
 * 失败时以 401 + 稳定错误码响应，原因可区分（缺失/未知/已过期/已注销）。
 */
@Component
@Order(1)
public class AuthSessionFilter extends OncePerRequestFilter {

    public static final String ATTR_USERNAME = "authenticatedUsername";
    public static final String ATTR_SESSION = "authenticatedSession";

    private final SessionManager sessionManager;
    private final SecurityProperties properties;

    public AuthSessionFilter(SessionManager sessionManager, SecurityProperties properties) {
        this.sessionManager = sessionManager;
        this.properties = properties;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/") || path.equals("/api/auth/login");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String sessionId = readSessionCookie(request);
        try {
            SessionRecord session = sessionManager.validateAndRenew(sessionId);
            request.setAttribute(ATTR_USERNAME, session.getUsername());
            request.setAttribute(ATTR_SESSION, session);
            chain.doFilter(request, response);
        } catch (AuthException ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"error\":\"" + ex.getReason().name() + "\"}");
        }
    }

    private String readSessionCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (properties.getCookieName().equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
