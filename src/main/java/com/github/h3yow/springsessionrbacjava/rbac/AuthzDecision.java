package com.github.h3yow.springsessionrbacjava.rbac;

/**
 * 授权判定结果，携带判定依据便于日志与测试断言。
 */
public record AuthzDecision(boolean permitted, String reason) {
    public static AuthzDecision permit(String reason) {
        return new AuthzDecision(true, reason);
    }

    public static AuthzDecision deny(String reason) {
        return new AuthzDecision(false, reason);
    }
}
