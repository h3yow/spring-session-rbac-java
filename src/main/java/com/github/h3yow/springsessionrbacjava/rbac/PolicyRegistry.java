package com.github.h3yow.springsessionrbacjava.rbac;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 资源级策略注册表：路径前缀 -> 所需角色。
 * 默认拒绝：无命中策略即拒绝。策略运行时可变，授权判定每次实时读取，变更即时生效。
 */
@Component
public class PolicyRegistry {

    private final Map<String, String> policies = new ConcurrentHashMap<>();

    public PolicyRegistry() {
        policies.put("/api/user", "USER");
        policies.put("/api/admin", "ADMIN");
    }

    public void setPolicy(String pathPattern, String requiredRole) {
        policies.put(pathPattern, requiredRole);
    }

    public void removePolicy(String pathPattern) {
        policies.remove(pathPattern);
    }

    /**
     * 最长前缀匹配。
     *
     * @return 命中策略所需角色；无命中策略时返回 empty（调用方按默认拒绝处理）。
     */
    public Optional<String> requiredRoleFor(String path) {
        String best = null;
        for (String pattern : policies.keySet()) {
            if (path.startsWith(pattern) && (best == null || pattern.length() > best.length())) {
                best = pattern;
            }
        }
        return best == null ? Optional.empty() : Optional.ofNullable(policies.get(best));
    }
}
