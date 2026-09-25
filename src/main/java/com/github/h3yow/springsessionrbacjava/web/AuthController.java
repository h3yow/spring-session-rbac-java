package com.github.h3yow.springsessionrbacjava.web;

import com.github.h3yow.springsessionrbacjava.auth.AuthResult;
import com.github.h3yow.springsessionrbacjava.auth.AuthService;
import com.github.h3yow.springsessionrbacjava.config.SecurityProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 认证端点：登录、注销、续期、当前身份查询。
 * 登录失败统一 401 + INVALID_CREDENTIALS，不区分账号不存在与口令错误。
 */
@RestController
public class AuthController {

    private final AuthService authService;
    private final CookieFactory cookieFactory;
    private final SecurityProperties properties;

    public AuthController(AuthService authService, CookieFactory cookieFactory,
                          SecurityProperties properties) {
        this.authService = authService;
        this.cookieFactory = cookieFactory;
        this.properties = properties;
    }

    public record LoginRequest(String username, String password) {
    }

    @PostMapping("/auth/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest request) {
        AuthResult result = authService.login(request.username(), request.password());
        if (!result.success()) {
            return ResponseEntity.status(401).body(Map.of(
                    "error", "UNAUTHORIZED",
                    "reason", result.reason().name()));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "OK");
        body.put("csrfToken", result.csrfToken());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,
                        cookieFactory.sessionCookie(result.sessionId(),
                                properties.getSessionTtlSeconds()))
                .body(body);
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request) {
        String sessionId = SessionInterceptor.readSessionCookie(request);
        authService.logout(sessionId);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookieFactory.clearSessionCookie())
                .body(Map.of("status", "OK"));
    }

    @PostMapping("/auth/renew")
    public ResponseEntity<Map<String, Object>> renew(HttpServletRequest request) {
        String sessionId = SessionInterceptor.readSessionCookie(request);
        AuthResult result = authService.renew(sessionId);
        if (!result.success()) {
            return ResponseEntity.status(401).body(Map.of(
                    "error", "UNAUTHORIZED",
                    "reason", result.reason().name()));
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,
                        cookieFactory.sessionCookie(sessionId, properties.getSessionTtlSeconds()))
                .body(Map.of("status", "OK"));
    }

    @GetMapping("/auth/whoami")
    public ResponseEntity<Map<String, Object>> whoami(HttpServletRequest request) {
        String sessionId = SessionInterceptor.readSessionCookie(request);
        AuthResult result = authService.resolve(sessionId);
        if (!result.success()) {
            return ResponseEntity.status(401).body(Map.of(
                    "error", "UNAUTHORIZED",
                    "reason", result.reason().name()));
        }
        return ResponseEntity.ok(Map.of("username", authService.usernameOf(sessionId)));
    }
}
