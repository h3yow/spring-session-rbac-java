package com.github.h3yow.springsessionrbacjava.rbac;

import com.github.h3yow.springsessionrbacjava.auth.UserDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;

/**
 * 默认拒绝的授权服务。
 * 角色实时取自服务端 UserDirectory，客户端提交的角色/权限一律不参与判定；
 * 策略与角色变更后，已有会话的下一次请求即按新规则判定。
 */
@Service
public class AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationService.class);

    private final PolicyRegistry policyRegistry;
    private final UserDirectory userDirectory;

    public AuthorizationService(PolicyRegistry policyRegistry, UserDirectory userDirectory) {
        this.policyRegistry = policyRegistry;
        this.userDirectory = userDirectory;
    }

    public AuthzDecision authorize(String username, String path) {
        Optional<String> required = policyRegistry.requiredRoleFor(path);
        if (required.isEmpty()) {
            log.info("authz deny: user={}, path={}, reason=no-policy(default-deny)", username, path);
            return AuthzDecision.deny("no policy matched, default deny");
        }
        Set<String> roles = userDirectory.rolesOf(username);
        if (roles.contains(required.get())) {
            log.info("authz permit: user={}, path={}, required={}, roles={}",
                    username, path, required.get(), roles);
            return AuthzDecision.permit("role " + required.get() + " present");
        }
        log.info("authz deny: user={}, path={}, required={}, roles={}",
                username, path, required.get(), roles);
        return AuthzDecision.deny("missing role " + required.get());
    }
}
