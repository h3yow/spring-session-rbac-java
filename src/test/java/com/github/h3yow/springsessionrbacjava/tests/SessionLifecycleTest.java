package com.github.h3yow.springsessionrbacjava.tests;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import com.github.h3yow.springsessionrbacjava.security.AuthException;
import com.github.h3yow.springsessionrbacjava.security.AuthFailureReason;
import com.github.h3yow.springsessionrbacjava.security.AuthService;
import com.github.h3yow.springsessionrbacjava.security.InMemoryUserDirectory;
import com.github.h3yow.springsessionrbacjava.security.SecurityProperties;
import com.github.h3yow.springsessionrbacjava.security.SessionManager;
import com.github.h3yow.springsessionrbacjava.security.SessionRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 会话生命周期：登录、续期、过期、注销、并发上限、会话固定防护。
 */
class SessionLifecycleTest {

    private static final Logger log = LoggerFactory.getLogger(SessionLifecycleTest.class);

    private SecurityProperties properties;
    private InMemoryUserDirectory userDirectory;
    private SessionManager sessionManager;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        properties = new SecurityProperties();
        properties.setSessionTtl(Duration.ofMinutes(30));
        properties.setMaxConcurrentSessions(2);
        userDirectory = new InMemoryUserDirectory();
        sessionManager = new SessionManager(properties);
        authService = new AuthService(userDirectory, sessionManager);
    }

    @Test
    void loginSuccessCreatesSession() {
        log.info("输入: username=alice, password=正确口令");
        SessionRecord session = authService.login("alice", "alice-pass");
        log.info("判定依据: 口令哈希匹配 -> 建立会话 id={}, csrfToken 已生成", session.getId());
        assertEquals("alice", session.getUsername());
        assertNotEquals(session.getId(), session.getCsrfToken());
    }

    @Test
    void wrongPasswordAndUnknownUserAreIndistinguishable() {
        log.info("输入: (alice, 错误口令) 与 (不存在的用户, 任意口令)");
        AuthException wrongPassword = assertThrows(AuthException.class,
                () -> authService.login("alice", "wrong"));
        AuthException unknownUser = assertThrows(AuthException.class,
                () -> authService.login("no-such-user", "wrong"));
        log.info("判定依据: 两种失败原因均为 {}, 响应不可区分账号是否存在", wrongPassword.getReason());
        assertEquals(AuthFailureReason.INVALID_CREDENTIALS, wrongPassword.getReason());
        assertEquals(wrongPassword.getReason(), unknownUser.getReason());
    }

    @Test
    void eachLoginRotatesSessionId() {
        SessionRecord first = authService.login("alice", "alice-pass");
        SessionRecord second = authService.login("alice", "alice-pass");
        log.info("判定依据: 两次登录会话 id 不同 ({} != {}), 防止会话固定", first.getId(), second.getId());
        assertNotEquals(first.getId(), second.getId());
    }

    @Test
    void expiredSessionIsRejectedWithDistinctReason() {
        MutableClock clock = new MutableClock(Instant.now());
        sessionManager.setClock(clock);
        SessionRecord session = authService.login("alice", "alice-pass");
        clock.advance(Duration.ofMinutes(31));
        log.info("输入: 已过期会话 id={}", session.getId());
        AuthException ex = assertThrows(AuthException.class,
                () -> sessionManager.validateAndRenew(session.getId()));
        log.info("判定依据: now 超过 expiresAt -> {}", ex.getReason());
        assertEquals(AuthFailureReason.SESSION_EXPIRED, ex.getReason());
    }

    @Test
    void revokedAndUnknownSessionsHaveDistinctReasons() {
        SessionRecord session = authService.login("alice", "alice-pass");
        authService.logout(session.getId());
        AuthException revoked = assertThrows(AuthException.class,
                () -> sessionManager.validateAndRenew(session.getId()));
        AuthException unknown = assertThrows(AuthException.class,
                () -> sessionManager.validateAndRenew("never-issued-id"));
        log.info("判定依据: 已注销 -> {}, 未知 id -> {}, 原因可区分", revoked.getReason(), unknown.getReason());
        assertEquals(AuthFailureReason.SESSION_REVOKED, revoked.getReason());
        assertEquals(AuthFailureReason.SESSION_INVALID, unknown.getReason());
    }

    @Test
    void renewalSlidesExpiry() {
        MutableClock clock = new MutableClock(Instant.now());
        sessionManager.setClock(clock);
        SessionRecord session = authService.login("alice", "alice-pass");
        clock.advance(Duration.ofMinutes(20));
        SessionRecord renewed = sessionManager.validateAndRenew(session.getId());
        log.info("判定依据: 访问后续期, expiresAt={} 应晚于原过期时间", renewed.getExpiresAt());
        assertTrue(renewed.getExpiresAt().isAfter(session.getCreatedAt().plus(Duration.ofMinutes(30))));
    }

    @Test
    void concurrentSessionLimitEvictsOldest() {
        SessionRecord s1 = authService.login("alice", "alice-pass");
        SessionRecord s2 = authService.login("alice", "alice-pass");
        SessionRecord s3 = authService.login("alice", "alice-pass");
        log.info("判定依据: 上限=2, 第三次登录应淘汰最早会话 s1");
        AuthException ex = assertThrows(AuthException.class,
                () -> sessionManager.validateAndRenew(s1.getId()));
        assertEquals(AuthFailureReason.SESSION_REVOKED, ex.getReason());
        assertEquals("alice", sessionManager.validateAndRenew(s2.getId()).getUsername());
        assertEquals("alice", sessionManager.validateAndRenew(s3.getId()).getUsername());
    }

    @Test
    void concurrentLoginsNeverExceedLimit() throws Exception {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<SessionRecord>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> authService.login("alice", "alice-pass"));
        }
        List<Future<SessionRecord>> futures = pool.invokeAll(tasks);
        pool.shutdown();

        AtomicInteger active = new AtomicInteger();
        for (Future<SessionRecord> future : futures) {
            SessionRecord session = future.get();
            try {
                sessionManager.validateAndRenew(session.getId());
                active.incrementAndGet();
            } catch (AuthException ex) {
                log.info("会话 {} 被淘汰, 原因={}", session.getId(), ex.getReason());
            }
        }
        log.info("判定依据: {} 个并发登录后活跃会话数={}, 不得超过上限 2", threads, active.get());
        assertEquals(properties.getMaxConcurrentSessions(), active.get());
    }

    @Test
    void duplicateLogoutIsIdempotent() {
        SessionRecord session = authService.login("alice", "alice-pass");
        authService.logout(session.getId());
        authService.logout(session.getId());
        AuthException ex = assertThrows(AuthException.class,
                () -> sessionManager.validateAndRenew(session.getId()));
        log.info("判定依据: 重复注销后状态一致, 原因={}", ex.getReason());
        assertEquals(AuthFailureReason.SESSION_REVOKED, ex.getReason());
    }

    /** 可手动推进的测试时钟。 */
    static final class MutableClock extends Clock {
        private Instant instant;

        MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public Instant instant() {
            return instant;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
