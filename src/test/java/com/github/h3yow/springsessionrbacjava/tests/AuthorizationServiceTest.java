package com.github.h3yow.springsessionrbacjava.tests;

import com.github.h3yow.springsessionrbacjava.auth.UserDirectory;
import com.github.h3yow.springsessionrbacjava.rbac.AuthorizationService;
import com.github.h3yow.springsessionrbacjava.rbac.AuthzDecision;
import com.github.h3yow.springsessionrbacjava.rbac.PolicyRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AuthorizationServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServiceTest.class);

    private UserDirectory userDirectory;
    private PolicyRegistry policyRegistry;
    private AuthorizationService authorizationService;

    @BeforeEach
    void setUp() {
        userDirectory = new UserDirectory();
        policyRegistry = new PolicyRegistry();
        authorizationService = new AuthorizationService(policyRegistry, userDirectory);
    }

    @Test
    void defaultDenyWhenNoPolicyMatches() {
        AuthzDecision d = authorizationService.authorize("alice", "/api/unknown/thing");
        log.info("user=alice path=/api/unknown/thing -> permitted={}, basis={}", d.permitted(), d.reason());
        assertFalse(d.permitted(), "无策略命中必须默认拒绝");
    }

    @Test
    void roleBasedPermitAndDeny() {
        AuthzDecision userOk = authorizationService.authorize("alice", "/api/user/profile");
        AuthzDecision adminDenied = authorizationService.authorize("alice", "/api/admin/dashboard");
        AuthzDecision adminOk = authorizationService.authorize("bob", "/api/admin/dashboard");
        log.info("alice->/api/user: {}, alice->/api/admin: {} ({}), bob->/api/admin: {}",
                userOk.permitted(), adminDenied.permitted(), adminDenied.reason(), adminOk.permitted());
        assertTrue(userOk.permitted());
        assertFalse(adminDenied.permitted());
        assertTrue(adminOk.permitted());
    }

    @Test
    void roleChangeTakesEffectImmediatelyForExistingSessions() {
        // 模拟 alice 已登录（会话不快照角色），运行时被回收 USER 角色
        assertTrue(authorizationService.authorize("alice", "/api/user/profile").permitted());
        userDirectory.setRoles("alice", Set.of());
        AuthzDecision after = authorizationService.authorize("alice", "/api/user/profile");
        log.info("after role revoke: permitted={}, basis={}", after.permitted(), after.reason());
        assertFalse(after.permitted(), "角色变更后已有会话必须按新角色即时判定");

        userDirectory.setRoles("alice", Set.of("USER", "ADMIN"));
        assertTrue(authorizationService.authorize("alice", "/api/admin/dashboard").permitted(),
                "角色授予后即时生效");
    }

    @Test
    void policyChangeTakesEffectImmediately() {
        assertTrue(authorizationService.authorize("alice", "/api/user/profile").permitted());
        policyRegistry.setPolicy("/api/user", "ADMIN");
        AuthzDecision after = authorizationService.authorize("alice", "/api/user/profile");
        log.info("after policy tighten: permitted={}, basis={}", after.permitted(), after.reason());
        assertFalse(after.permitted(), "策略收紧后即时拒绝");
        policyRegistry.removePolicy("/api/user");
        AuthzDecision removed = authorizationService.authorize("alice", "/api/user/profile");
        assertFalse(removed.permitted(), "策略移除后回到默认拒绝");
    }

    @Test
    void clientSuppliedRolesNeverParticipate() {
        // 授权入口只接受 username + path，角色只能来自服务端目录；
        // 此处验证：即使客户端声称自己是 ADMIN，判定仍按服务端数据。
        AuthzDecision d = authorizationService.authorize("alice", "/api/admin/dashboard");
        log.info("alice (server roles={}) -> /api/admin: permitted={}, basis={}",
                userDirectory.rolesOf("alice"), d.permitted(), d.reason());
        assertFalse(d.permitted());
        assertFalse(userDirectory.rolesOf("alice").contains("ADMIN"));
    }
}
