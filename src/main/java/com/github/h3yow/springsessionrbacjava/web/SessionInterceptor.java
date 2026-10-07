package com.github.h3yow.springsessionrbacjava.web;

import com.github.h3yow.springsessionrbacjava.auth.AuthResult;
import com.github.h3yow.springsessionrbacjava.auth.AuthService;
import com.github.h3yow.springsessionrbacjava.rbac.AuthorizationService;
import com.github.h3yow.springsessionrbacjava.rbac.AuthzDecision;
import com.github.h3yow.springsessionrbacjava.session.SessionStore;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.time.Instant;

/**
 * 会话解析 + 授权拦截器，作用于 /api/** 受保护资源。
 * <ul>
 *   <li>未认证：401，body 中 reason 可区分（SESSION_MISSING/EXPIRED/REVOKED），
 *       判定发生在资源查找之前，不泄露资源存在性；</li>
 *   <li>已认证但越权：一律 404，与资源不存在时响应一致，不暴露资源是否存在；</li>
 *   <li>客户端提交的角色/权限参数不参与判定，身份只取自服务端会话。</li>
 * </ul>
 */
public class SessionInterceptor implements HandlerInterceptor {

    public static final String ATTR_USERNAME = "auth.username";
    public static final String ATTR_SESSION_ID = "auth.sessionId";

    private static final Logger log = LoggerFactory.getLogger(SessionInterceptor.class);

    private final AuthService authService;
    private final AuthorizationService authorizationService;
    private final SessionStore sessionStore;

    public SessionInterceptor(AuthService authService, AuthorizationService authorizationService,
                              SessionStore sessionStore) {
        this.authService = authService;
        this.authorizationService = authorizationService;
        this.sessionStore = sessionStore;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) throws IOException {
        String sessionId = readSessionCookie(request);
        AuthResult resolved = authService.resolve(sessionId);
        if (!resolved.success()) {
            log.info("request rejected: path={}, reason={}", request.getRequestURI(), resolved.reason());
            writeJson(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "{\"error\":\"UNAUTHORIZED\",\"reason\":\"" + resolved.reason() + "\"}");
            return false;
        }
        String username = authService.usernameOf(sessionId);
        AuthzDecision decision = authorizationService.authorize(username, request.getRequestURI());
        if (!decision.permitted()) {
            log.info("request forbidden: user={}, path={}, basis={}",
                    username, request.getRequestURI(), decision.reason());
            // 与资源不存在时响应一致，不暴露资源存在性。
            writeJson(response, HttpServletResponse.SC_NOT_FOUND, "{\"error\":\"NOT_FOUND\"}");
            return false;
        }
        request.setAttribute(ATTR_USERNAME, username);
        request.setAttribute(ATTR_SESSION_ID, sessionId);
        // 认证+授权均通过后刷新最近活动时间，供会话列表展示；终态会话的 touch 为空操作。
        sessionStore.touch(sessionId, Instant.now());
        return true;
    }

    static String readSessionCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie c : cookies) {
            if (CookieFactory.SESSION_COOKIE.equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }

    static void writeJson(HttpServletResponse response, int status, String body) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write(body);
    }
}
