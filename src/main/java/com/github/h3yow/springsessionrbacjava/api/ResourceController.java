package com.github.h3yow.springsessionrbacjava.api;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.github.h3yow.springsessionrbacjava.security.PolicyService;
import com.github.h3yow.springsessionrbacjava.security.web.AuthSessionFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 受保护资源示例。授权只依据服务端会话身份与实时策略，
 * 客户端提交的任何角色/权限信息不参与判定。
 */
@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    private final PolicyService policyService;
    /** 幂等键 -> 已完成的转账结果，防止重复提交产生不一致状态。 */
    private final Map<String, Map<String, Object>> processedTransfers = new ConcurrentHashMap<>();

    public ResourceController(PolicyService policyService) {
        this.policyService = policyService;
    }

    @GetMapping("/user")
    public Map<String, Object> userResource(HttpServletRequest request) {
        String username = (String) request.getAttribute(AuthSessionFilter.ATTR_USERNAME);
        policyService.requireAccess(username, "/api/resources/user");
        return Map.of("resource", "user", "username", username);
    }

    @GetMapping("/admin")
    public Map<String, Object> adminResource(HttpServletRequest request) {
        String username = (String) request.getAttribute(AuthSessionFilter.ATTR_USERNAME);
        policyService.requireAccess(username, "/api/resources/admin");
        return Map.of("resource", "admin", "username", username);
    }

    public record TransferRequest(String toAccount, long amount) {
    }

    /**
     * 高风险操作：需会话 + CSRF 令牌 + USER 角色。
     * 通过 Idempotency-Key 保证重复/并发提交返回同一结果且只执行一次。
     */
    @PostMapping("/transfer")
    public Map<String, Object> transfer(HttpServletRequest request,
                                        @RequestBody TransferRequest body,
                                        @RequestHeader("Idempotency-Key") String idempotencyKey) {
        String username = (String) request.getAttribute(AuthSessionFilter.ATTR_USERNAME);
        policyService.requireAccess(username, "/api/resources/transfer");
        String key = username + ":" + idempotencyKey;
        return processedTransfers.computeIfAbsent(key, k -> Map.of(
                "status", "completed",
                "from", username,
                "to", body.toAccount(),
                "amount", body.amount()));
    }
}
