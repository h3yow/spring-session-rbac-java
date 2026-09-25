package com.github.h3yow.springsessionrbacjava.api;

import java.util.Map;

import com.github.h3yow.springsessionrbacjava.security.AuthService;
import com.github.h3yow.springsessionrbacjava.security.SessionRecord;
import com.github.h3yow.springsessionrbacjava.security.SecurityProperties;
import com.github.h3yow.springsessionrbacjava.security.web.AuthSessionFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 认证入口：登录（建立会话 + 安全 Cookie）、注销（幂等）、会话信息。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final SecurityProperties properties;

    public AuthController(AuthService authService, SecurityProperties properties) {
        this.authService = authService;
        this.properties = properties;
    }

    public record LoginRequest(String username, String password) {
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest request) {
        SessionRecord session = authService.login(request.username(), request.password());
        ResponseCookie cookie = ResponseCookie.from(properties.getCookieName(), session.getId())
                .httpOnly(true)
                .secure(properties.isCookieSecure())
                .sameSite("Strict")
                .path("/")
                .maxAge(properties.getSessionTtl())
                .build();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(Map.of(
                        "username", session.getUsername(),
                        "csrfToken", session.getCsrfToken(),
                        "expiresAt", session.getExpiresAt().toString()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request) {
        SessionRecord session = (SessionRecord) request.getAttribute(AuthSessionFilter.ATTR_SESSION);
        if (session != null) {
            authService.logout(session.getId());
        }
        ResponseCookie cleared = ResponseCookie.from(properties.getCookieName(), "")
                .httpOnly(true)
                .secure(properties.isCookieSecure())
                .sameSite("Strict")
                .path("/")
                .maxAge(0)
                .build();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleared.toString())
                .body(Map.of("status", "logged_out"));
    }

    @GetMapping("/me")
    public Map<String, Object> me(HttpServletRequest request) {
        SessionRecord session = (SessionRecord) request.getAttribute(AuthSessionFilter.ATTR_SESSION);
        return Map.of(
                "username", session.getUsername(),
                "expiresAt", session.getExpiresAt().toString());
    }
}
