package com.github.h3yow.springsessionrbacjava.security.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Set;

import com.github.h3yow.springsessionrbacjava.security.AuthFailureReason;
import com.github.h3yow.springsessionrbacjava.security.SessionRecord;
import com.github.h3yow.springsessionrbacjava.security.SecurityProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * CSRF 过滤器：状态变更请求（POST/PUT/DELETE/PATCH）必须携带与会话绑定的令牌。
 * 在 AuthSessionFilter 之后运行，令牌取自服务端会话而非客户端自报。
 */
@Component
@Order(2)
public class CsrfFilter extends OncePerRequestFilter {

    private static final Set<String> MUTATING_METHODS = Set.of("POST", "PUT", "DELETE", "PATCH");

    private final SecurityProperties properties;

    public CsrfFilter(SecurityProperties properties) {
        this.properties = properties;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/")
                || path.equals("/api/auth/login")
                || !MUTATING_METHODS.contains(request.getMethod());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        SessionRecord session = (SessionRecord) request.getAttribute(AuthSessionFilter.ATTR_SESSION);
        String token = request.getHeader(properties.getCsrfHeaderName());
        if (token == null || token.isBlank()) {
            writeError(response, AuthFailureReason.CSRF_TOKEN_MISSING);
            return;
        }
        boolean matches = session != null && MessageDigest.isEqual(
                token.getBytes(StandardCharsets.UTF_8),
                session.getCsrfToken().getBytes(StandardCharsets.UTF_8));
        if (!matches) {
            writeError(response, AuthFailureReason.CSRF_TOKEN_MISMATCH);
            return;
        }
        chain.doFilter(request, response);
    }

    private void writeError(HttpServletResponse response, AuthFailureReason reason) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"error\":\"" + reason.name() + "\"}");
    }
}
