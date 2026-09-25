package com.github.h3yow.springsessionrbacjava.tests;

import java.util.Set;

import com.github.h3yow.springsessionrbacjava.security.AuthException;
import com.github.h3yow.springsessionrbacjava.security.AuthFailureReason;
import com.github.h3yow.springsessionrbacjava.security.InMemoryUserDirectory;
import com.github.h3yow.springsessionrbacjava.security.PolicyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 授权策略：默认拒绝、角色判定、策略与角色变更即时生效、越权不泄露资源存在性。
 */
class PolicyServiceTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyServiceTest.class);

    private InMemoryUserDirectory userDirectory;
    private PolicyService policyService;

    @BeforeEach
    void setUp() {
        userDirectory = new InMemoryUserDirectory();
        policyService = new PolicyService(userDirectory);
    }

    @Test
    void defaultDenyForUnknownResource() {
        log.info("输入: 无策略资源 /api/resources/unknown, 用户 alice(USER)");
        boolean allowed = policyService.isAllowed("alice", "/api/resources/unknown");
        log.info("判定依据: 默认拒绝 -> allowed={}", allowed);
        assertFalse(allowed);
    }

    @Test
    void roleBasedAllowAndDeny() {
        log.info("输入: alice(USER) 访问 /api/resources/user 与 /api/resources/admin");
        assertTrue(policyService.isAllowed("alice", "/api/resources/user"));
        assertFalse(policyService.isAllowed("alice", "/api/resources/admin"));
        log.info("判定依据: USER 角色可访问 user 资源, 不可访问 admin 资源");
        assertTrue(policyService.isAllowed("bob", "/api/resources/admin"));
    }

    @Test
    void policyChangeTakesEffectImmediately() {
        log.info("输入: 运行中将 /api/resources/admin 所需角色由 ADMIN 改为 USER");
        assertFalse(policyService.isAllowed("alice", "/api/resources/admin"));
        policyService.setRequiredRole("/api/resources/admin", "USER");
        boolean allowed = policyService.isAllowed("alice", "/api/resources/admin");
        log.info("判定依据: 策略即时生效, alice 现在 allowed={}", allowed);
        assertTrue(allowed);
    }

    @Test
    void roleChangeTakesEffectImmediatelyForExistingIdentity() {
        log.info("输入: 运行中收回 bob 的 ADMIN 角色");
        assertTrue(policyService.isAllowed("bob", "/api/resources/admin"));
        userDirectory.register("bob",
                new BCryptPasswordEncoder().encode("bob-pass"), Set.of("USER"));
        boolean allowed = policyService.isAllowed("bob", "/api/resources/admin");
        log.info("判定依据: 角色实时读取, bob 现在 allowed={}", allowed);
        assertFalse(allowed);
    }

    @Test
    void forbiddenAndNonexistentResourceAreIndistinguishable() {
        AuthException forbidden = assertThrows(AuthException.class,
                () -> policyService.requireAccess("alice", "/api/resources/admin"));
        AuthException nonexistent = assertThrows(AuthException.class,
                () -> policyService.requireAccess("alice", "/api/resources/does-not-exist"));
        log.info("判定依据: 越权与资源不存在均为 {}, 不暴露资源是否存在", forbidden.getReason());
        assertEquals(AuthFailureReason.RESOURCE_NOT_AVAILABLE, forbidden.getReason());
        assertEquals(forbidden.getReason(), nonexistent.getReason());
    }
}
