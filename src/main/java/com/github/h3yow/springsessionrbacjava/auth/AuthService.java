package com.github.h3yow.springsessionrbacjava.auth;

import com.github.h3yow.springsessionrbacjava.config.SecurityProperties;
import com.github.h3yow.springsessionrbacjava.session.SessionLookup;
import com.github.h3yow.springsessionrbacjava.session.SessionRecord;
import com.github.h3yow.springsessionrbacjava.session.SessionStore;
import com.github.h3yow.springsessionrbacjava.session.TerminationReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

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
        SessionLookup lookup = sessionStore.renew(sessionId, properties.getSessionTtlSeconds());
        return switch (lookup.state()) {
            case ACTIVE -> {
                log.info("renew success: sessionId={}", sessionId);
                yield AuthResult.ok(sessionId, lookup.record().csrfToken());
            }
            case TERMINATED -> AuthResult.fail(toFailureReason(lookup.reason()));
            case UNKNOWN -> AuthResult.fail(AuthFailureReason.SESSION_MISSING);
        };
    }

    /**
     * 解析会话并校验有效性，失败原因可区分：
     * 缺失（不存在/伪造）/ 主动注销（SESSION_REVOKED）/ 被挤掉（SESSION_CAP_EVICTED）/
     * 自然过期（SESSION_EXPIRED）。资源访问、续期、会话管理各入口结论一致。
     */
    public AuthResult resolve(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return AuthResult.fail(AuthFailureReason.SESSION_MISSING);
        }
        SessionLookup lookup = sessionStore.lookup(sessionId);
        return switch (lookup.state()) {
            case ACTIVE -> AuthResult.ok(lookup.record().id(), lookup.record().csrfToken());
            case TERMINATED -> {
                AuthFailureReason reason = toFailureReason(lookup.reason());
                log.info("resolve terminated session: sessionId={}, reason={}", sessionId, reason);
                yield AuthResult.fail(reason);
            }
            case UNKNOWN -> AuthResult.fail(AuthFailureReason.SESSION_MISSING);
        };
    }

    static AuthFailureReason toFailureReason(TerminationReason reason) {
        return switch (reason) {
            case LOGOUT -> AuthFailureReason.SESSION_REVOKED;
            case CAP_EVICTED -> AuthFailureReason.SESSION_CAP_EVICTED;
            case EXPIRED -> AuthFailureReason.SESSION_EXPIRED;
        };
    }

    public String usernameOf(String sessionId) {
        return sessionStore.find(sessionId).map(SessionRecord::username).orElse(null);
    }
}
