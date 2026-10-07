package com.github.h3yow.springsessionrbacjava.management;

import com.github.h3yow.springsessionrbacjava.session.SessionView;
import com.github.h3yow.springsessionrbacjava.web.SessionInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 自助会话管理端点（挂在 /api/sessions/** 下，与其他受保护资源一样需要有效会话 + 角色 + CSRF）。
 * 只暴露当前账号自己的信息；越权/不存在返回逐字节一致的 404，不泄露会话或账号存在性。
 */
@RestController
public class SessionController {

    private final SessionManagementService managementService;

    public SessionController(SessionManagementService managementService) {
        this.managementService = managementService;
    }

    @GetMapping("/api/sessions")
    public Map<String, Object> list(HttpServletRequest request) {
        String username = (String) request.getAttribute(SessionInterceptor.ATTR_USERNAME);
        String currentSessionId = (String) request.getAttribute(SessionInterceptor.ATTR_SESSION_ID);
        List<SessionView> sessions = managementService.listSessions(username, currentSessionId);
        return Map.of("sessions", sessions);
    }

    @PostMapping("/api/sessions/{sessionId}/terminate")
    public ResponseEntity<Map<String, Object>> terminate(HttpServletRequest request,
                                                         @PathVariable String sessionId) {
        String username = (String) request.getAttribute(SessionInterceptor.ATTR_USERNAME);
        TerminateStatus status = managementService.terminate(username, sessionId);
        if (status == TerminateStatus.NOT_FOUND) {
            // 与资源不存在/越权的既有约定一致，不泄露目标会话是否存在、归属于谁。
            return ResponseEntity.status(404).body(Map.of("error", "NOT_FOUND"));
        }
        return ResponseEntity.ok(Map.of("status", "OK"));
    }

    @PostMapping("/api/sessions/terminate-others")
    public Map<String, Object> terminateOthers(HttpServletRequest request) {
        String username = (String) request.getAttribute(SessionInterceptor.ATTR_USERNAME);
        String currentSessionId = (String) request.getAttribute(SessionInterceptor.ATTR_SESSION_ID);
        int revoked = managementService.terminateOthers(username, currentSessionId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "OK");
        body.put("revoked", revoked);
        return body;
    }
}
