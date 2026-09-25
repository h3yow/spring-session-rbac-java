package com.github.h3yow.springsessionrbacjava.tests;

import com.github.h3yow.springsessionrbacjava.auth.AuthFailureReason;
import com.github.h3yow.springsessionrbacjava.auth.AuthResult;
import com.github.h3yow.springsessionrbacjava.auth.AuthService;
import com.github.h3yow.springsessionrbacjava.auth.UserDirectory;
import com.github.h3yow.springsessionrbacjava.config.SecurityProperties;
import com.github.h3yow.springsessionrbacjava.session.SessionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

class AuthServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceTest.class);

    private UserDirectory userDirectory;
    private SessionStore sessionStore;
    private SecurityProperties properties;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        userDirectory = new UserDirectory();
        sessionStore = new SessionStore();
        properties = new SecurityProperties();
        authService = new AuthService(userDirectory, sessionStore, properties);
    }

    @Test
    void loginSuccessIssuesSessionAndCsrfToken() {
        AuthResult r = authService.login("alice", "alice-pass");
        log.info("login alice: success={}, sessionId={}", r.success(), r.sessionId());
        assertTrue(r.success());
        assertNotNull(r.sessionId());
        assertNotNull(r.csrfToken());
        assertEquals("alice", authService.usernameOf(r.sessionId()));
    }

    @Test
    void unknownUserAndBadPasswordAreIndistinguishable() {
        AuthResult badPassword = authService.login("alice", "wrong");
        AuthResult unknownUser = authService.login("nosuchuser", "whatever");
        log.info("badPassword.reason={}, unknownUser.reason={}", badPassword.reason(), unknownUser.reason());
        assertFalse(badPassword.success());
        assertFalse(unknownUser.success());
        assertEquals(badPassword.reason(), unknownUser.reason(),
                "账号不存在与口令错误对外必须一致");
        assertEquals(AuthFailureReason.INVALID_CREDENTIALS, badPassword.reason());
    }

    @Test
    void sessionFailureReasonsAreDistinguishable() {
        AuthResult ok = authService.login("alice", "alice-pass");
        String sid = ok.sessionId();

        AuthResult missing = authService.resolve(null);
        AuthResult unknown = authService.resolve("no-such-session");
        assertEquals(AuthFailureReason.SESSION_MISSING, missing.reason());
        assertEquals(AuthFailureReason.SESSION_MISSING, unknown.reason());

        authService.logout(sid);
        AuthResult revoked = authService.resolve(sid);
        log.info("after logout: reason={}", revoked.reason());
        assertEquals(AuthFailureReason.SESSION_MISSING, revoked.reason(),
                "已注销会话从存储移除，按缺失处理");

        // 过期：ttl=0 的会话
        properties.setSessionTtlSeconds(0);
        AuthResult expiredLogin = authService.login("bob", "bob-pass");
        AuthResult expired = authService.resolve(expiredLogin.sessionId());
        log.info("expired session: reason={}", expired.reason());
        assertEquals(AuthFailureReason.SESSION_EXPIRED, expired.reason());

        log.info("reasons distinguishable: missing={}, expired={}", missing.reason(), expired.reason());
    }

    @Test
    void logoutIsIdempotentAndKillsSession() {
        AuthResult ok = authService.login("alice", "alice-pass");
        String sid = ok.sessionId();
        assertTrue(authService.logout(sid).success());
        AuthResult again = authService.logout(sid);
        log.info("double logout: second.success={}", again.success());
        assertTrue(again.success(), "重复注销返回稳定成功，不产生不一致状态");
        assertFalse(authService.renew(sid).success(), "已注销会话不得续期");
    }

    @Test
    void renewRefreshesLivingSessionOnly() {
        AuthResult ok = authService.login("alice", "alice-pass");
        AuthResult renewed = authService.renew(ok.sessionId());
        log.info("renew: success={}", renewed.success());
        assertTrue(renewed.success());
        assertEquals(AuthFailureReason.SESSION_MISSING, authService.renew("nope").reason());
    }

    @Test
    void concurrentLoginsAndLogoutsStayConsistent() throws InterruptedException {
        int threads = 12;
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(threads);
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.List<java.util.concurrent.Future<AuthResult>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                AuthResult r = authService.login("alice", "alice-pass");
                authService.logout(r.sessionId()); // 立即注销自己的会话
                return authService.resolve(r.sessionId());
            }));
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS));
        for (var f : futures) {
            AuthResult r = assertDoesNotThrow(() -> f.get());
            log.info("post-logout resolve: reason={}", r.reason());
            assertFalse(r.success(), "注销后并发解析不得成功");
            assertEquals(AuthFailureReason.SESSION_MISSING, r.reason());
        }
        assertEquals(0, sessionStore.activeCount("alice"), "竞争结束后状态必须一致、无残留");
    }
}
