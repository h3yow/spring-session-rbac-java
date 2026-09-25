package com.github.h3yow.springsessionrbacjava.security;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

/**
 * 授权策略：默认拒绝。资源 -> 所需角色的映射运行时可更新，
 * 角色在每次判定时从 UserDirectory 实时读取，已有会话即时按新策略判定。
 * 越权与资源不存在返回相同失败，不暴露资源是否存在。
 */
@Service
public class PolicyService {

    private final UserDirectory userDirectory;
    private final Map<String, String> requiredRoleByResource = new ConcurrentHashMap<>();

    public PolicyService(UserDirectory userDirectory) {
        this.userDirectory = userDirectory;
        // 初始策略（可被运行时覆盖）
        requiredRoleByResource.put("/api/resources/user", "USER");
        requiredRoleByResource.put("/api/resources/admin", "ADMIN");
        requiredRoleByResource.put("/api/resources/transfer", "USER");
    }

    /**
     * 判定用户是否可访问资源。无策略（默认拒绝）或角色不足均返回 false。
     */
    public boolean isAllowed(String username, String resource) {
        String requiredRole = requiredRoleByResource.get(resource);
        if (requiredRole == null) {
            return false; // 默认拒绝
        }
        Optional<UserAccount> account = userDirectory.findByUsername(username);
        return account.isPresent() && account.get().getRoles().contains(requiredRole);
    }

    /**
     * 越权或资源不存在时抛出同一失败，不区分两者。
     */
    public void requireAccess(String username, String resource) {
        if (!isAllowed(username, resource)) {
            throw new AuthException(AuthFailureReason.RESOURCE_NOT_AVAILABLE);
        }
    }

    public void setRequiredRole(String resource, String role) {
        requiredRoleByResource.put(resource, role);
    }

    public void removePolicy(String resource) {
        requiredRoleByResource.remove(resource);
    }
}
