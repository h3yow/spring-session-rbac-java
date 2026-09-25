package com.github.h3yow.springsessionrbacjava.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * 认证服务：登录（口令校验 + 会话建立）、注销。
 * 对“用户不存在”与“口令错误”返回完全相同的失败，且都执行哈希比较以避免时序泄露。
 */
@Service
public class AuthService {

    /** 用于未知用户的哑哈希，保证比较路径一致。 */
    private static final String DUMMY_HASH =
            new BCryptPasswordEncoder().encode("dummy-password-for-uniform-timing");

    private final UserDirectory userDirectory;
    private final SessionManager sessionManager;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public AuthService(UserDirectory userDirectory, SessionManager sessionManager) {
        this.userDirectory = userDirectory;
        this.sessionManager = sessionManager;
    }

    /**
     * 登录：校验口令并建立新会话（每次登录生成全新会话 id，防止会话固定）。
     */
    public SessionRecord login(String username, String password) {
        UserAccount account = userDirectory.findByUsername(username).orElse(null);
        String hashToCheck = account != null ? account.getPasswordHash() : DUMMY_HASH;
        boolean matches = passwordEncoder.matches(password == null ? "" : password, hashToCheck);
        if (account == null || !matches) {
            throw new AuthException(AuthFailureReason.INVALID_CREDENTIALS);
        }
        return sessionManager.createSession(account.getUsername());
    }

    /**
     * 注销：幂等，重复注销结果一致。
     */
    public void logout(String sessionId) {
        sessionManager.invalidate(sessionId);
    }
}
