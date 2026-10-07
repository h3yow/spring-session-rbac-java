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
            // 并发下会话刚被下线或刚过期：重新解析以拿到与其他入口一致的真实原因。
            log.info("renew race: sessionId={}, re-resolving", sessionId);
            return resolve(sessionId);
        }
        String csrf = sessionStore.find(sessionId).map(SessionRecord::csrfToken).orElse(null);
        return AuthResult.ok(sessionId, csrf);
    }

    /**
     * 解析会话并校验有效性，失败原因可区分：
     * <ul>
     *   <li>无/伪造/已过保留期：SESSION_MISSING（与从未存在不可区分，不泄露任何账号/会话存在性）；</li>
     *   <li>本人注销或被本人在会话管理中下线：SESSION_REVOKED；</li>
     *   <li>超并发上限被新登录挤掉：SESSION_CAP_EVICTED；</li>
     *   <li>自然过期（保留宽限内仍可分辨）：SESSION_EXPIRED。</li>
     * </ul>
     * 资源访问与会话续期等入口共用本方法，结论保持一致。
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
            AuthFailureReason reason = switch (record.revocationReason()) {
                case CAP_EVICTED -> AuthFailureReason.SESSION_CAP_EVICTED;
                // 本人在本会话注销、或本人在会话管理中下线，都属于账号持有人主动撤销。
                case SELF_LOGOUT, USER_TERMINATED, NONE -> AuthFailureReason.SESSION_REVOKED;
            };
            log.info("session inactive: sessionId={}, revocationReason={}, mapped={}",
                    sessionId, record.revocationReason(), reason);
            return AuthResult.fail(reason);
        }
        if (record.isExpired(Instant.now())) {
            return AuthResult.fail(AuthFailureReason.SESSION_EXPIRED);
        }
        // 活跃会话：记录最近一次已认证活动，供会话列表展示。
        sessionStore.touch(sessionId);
        return AuthResult.ok(record.id(), record.csrfToken());
    }

    public String usernameOf(String sessionId) {
        return sessionStore.find(sessionId).map(SessionRecord::username).orElse(null);
    }
}
