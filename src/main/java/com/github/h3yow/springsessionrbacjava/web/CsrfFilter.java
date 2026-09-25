package com.github.h3yow.springsessionrbacjava.web;

import com.github.h3yow.springsessionrbacjava.auth.AuthFailureReason;
import com.github.h3yow.springsessionrbacjava.session.SessionStore;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * CSRF 防护：对携带会话 Cookie 的状态变更请求（POST/PUT/DELETE/PATCH），
 * 要求 X-CSRF-TOKEN 头与服务端会话绑定令牌一致（常量时间比较）。
 * 登录端点豁免（此时尚无会话，靠 SameSite=Strict + 凭据校验防护）。
 */
public class CsrfFilter extends OncePerRequestFilter {

    public static final String CSRF_HEADER = "X-CSRF-TOKEN";

    private static final Logger log = LoggerFactory.getLogger(CsrfFilter.class);
    private static final Set<String> STATE_CHANGING = Set.of("POST", "PUT", "DELETE", "PATCH");

    private final SessionStore sessionStore;

    public CsrfFilter(SessionStore sessionStore) {
        this.sessionStore = sessionStore;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        if (!STATE_CHANGING.contains(request.getMethod())
                || request.getRequestURI().equals("/auth/login")) {
            chain.doFilter(request, response);
            return;
        }
        String sessionId = SessionInterceptor.readSessionCookie(request);
        if (sessionId == null) {
            // 无会话的匿名状态变更请求交由下游认证逻辑处理。
            chain.doFilter(request, response);
            return;
        }
        String expected = sessionStore.find(sessionId)
                .map(com.github.h3yow.springsessionrbacjava.session.SessionRecord::csrfToken)
                .orElse(null);
        if (expected == null) {
            // 会话已注销/不存在（如并发重复注销）：交由下游认证逻辑统一处理，
            // 保证重复提交得到稳定结果而非 CSRF 错误。
            chain.doFilter(request, response);
            return;
        }
        String provided = request.getHeader(CSRF_HEADER);
        if (provided == null || provided.isBlank()) {
            log.info("csrf reject: path={}, reason=token-missing", request.getRequestURI());
            reject(response, AuthFailureReason.CSRF_TOKEN_MISSING);
            return;
        }
        if (!MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), provided.getBytes(StandardCharsets.UTF_8))) {
            log.info("csrf reject: path={}, reason=token-mismatch", request.getRequestURI());
            reject(response, AuthFailureReason.CSRF_TOKEN_MISMATCH);
            return;
        }
        chain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, AuthFailureReason reason) throws IOException {
        SessionInterceptor.writeJson(response, HttpServletResponse.SC_FORBIDDEN,
                "{\"error\":\"FORBIDDEN\",\"reason\":\"" + reason + "\"}");
    }
}
