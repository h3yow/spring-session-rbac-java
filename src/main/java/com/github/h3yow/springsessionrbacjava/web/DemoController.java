package com.github.h3yow.springsessionrbacjava.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 演示资源：公开端点、USER 端点、ADMIN 端点与高风险状态变更端点。
 * 身份只取自服务端会话（拦截器写入的请求属性），客户端提交的角色参数一律忽略。
 */
@RestController
public class DemoController {

    @GetMapping("/api/public/hello")
    public Map<String, Object> hello() {
        return Map.of("message", "hello");
    }

    @GetMapping("/api/user/profile")
    public Map<String, Object> profile(HttpServletRequest request) {
        return Map.of("username", request.getAttribute(SessionInterceptor.ATTR_USERNAME));
    }

    @GetMapping("/api/admin/dashboard")
    public Map<String, Object> dashboard(HttpServletRequest request) {
        return Map.of("username", request.getAttribute(SessionInterceptor.ATTR_USERNAME),
                "scope", "admin");
    }

    /** 高风险操作：需 USER 角色 + CSRF 令牌（由过滤器强制）。 */
    @PostMapping("/api/user/transfer")
    public Map<String, Object> transfer(HttpServletRequest request) {
        return Map.of("status", "DONE",
                "by", request.getAttribute(SessionInterceptor.ATTR_USERNAME));
    }
}
