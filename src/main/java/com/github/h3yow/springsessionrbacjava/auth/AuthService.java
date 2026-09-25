package com.github.h3yow.springsessionrbacjava.auth;

import com.github.h3yow.springsessionrbacjava.config.SecurityProperties;
import com.github.h3yow.springsessionrbacjava.session.SessionRecord;
import com.github.h3yow.springsessionrbacjava.session.SessionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

/**
 * 认证服务：登录（每次签发全新会话 ID，防会话固定）、注销、续期、会话解析。
 * 对外统一 INVALID_CREDENTIALS，不区分"账号不存在"与"口令错误"；
 * 会话类失败（缺失/过期/已注销）通过 AuthResult.reason 可区分。
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserDirectory userDirectory;
    private final SessionStore sessionStore;
    private final SecurityProperties properties;

    public AuthService(UserDirectory userDirectory, SessionStore sessionStore,
                       SecurityProperties properties) {
        this.userDirectory = userDirectory;
        this.sessionStore = sessionStore;
        this.properties = properties;
    }

    public AuthResult login(String username, String password) {
        boolean ok = userDirectory.verifyPassword(username, password);
        if (!ok) {
            // 内部日志可区分，对外统一 INVALID_CREDENTIALS，不泄露账号是否存在。
            boolean exists = userDirectory.findByUsername(username).isPresent();
            log.info("login failed: username={}, exists={}", username, exists);
            return AuthResult.fail(AuthFailureReason.INVALID_CREDENTIALS);
        }
        SessionRecord record = sessionStore.create(username,
                properties.getSessionTtlSeconds(), properties.getMaxConcurrentSessions());
        log.info("login success: username={}, sessionId={}", username, record.id());
        return AuthResult.ok(record.id(), record.csrfToken());
    }

    /** 注销，幂等：重复注销返回相同的稳定结果。 */
    public AuthResult logout(String sessionId) {
        if (sessionId == null) {
            return AuthResult.fail(AuthFailureReason.SESSION_MISSING);
        }
        boolean removed = sessionStore.revoke(sessionId);
        log.info("logout: sessionId={}, removed={}", sessionId, removed);
        // 幂等：已注销/不存在也视为成功，避免重复提交产生不一致。
        return AuthResult.ok(null, null);
    }

    public AuthResult renew(String sessionId) {
        AuthResult resolved = resolve(sessionId);
        if (!resolved.success()) {
            return resolved;
        }
        boolean renewed = sessionStore.renew(sessionId, properties.getSessionTtlSeconds());
        if (!renewed) {
            // 并发下会话刚被注销或过期：回滚到一致状态，报稳定错误。
            return AuthResult.fail(AuthFailureReason.SESSION_REVOKED);
        }
        String csrf = sessionStore.find(sessionId).map(SessionRecord::csrfToken).orElse(null);
        return AuthResult.ok(sessionId, csrf);
    }

    /**
     * 解析会话并校验有效性，失败原因可区分（缺失/已注销/过期）。
     */
    public AuthResult resolve(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return AuthResult.fail(AuthFailureReason.SESSION_MISSING);
        }
        Optional<SessionRecord> found = sessionStore.find(sessionId);
        if (found.isEmpty()) {
            return AuthResult.fail(AuthFailureReason.SESSION_MISSING);
        }
        SessionRecord record = found.get();
        if (record.isRevoked()) {
            return AuthResult.fail(AuthFailureReason.SESSION_REVOKED);
        }
        if (record.isExpired(Instant.now())) {
            return AuthResult.fail(AuthFailureReason.SESSION_EXPIRED);
        }
        return AuthResult.ok(record.id(), record.csrfToken());
    }

    public String usernameOf(String sessionId) {
        return sessionStore.find(sessionId).map(SessionRecord::username).orElse(null);
    }
}
