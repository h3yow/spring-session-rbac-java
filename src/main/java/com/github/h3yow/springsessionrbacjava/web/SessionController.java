package com.github.h3yow.springsessionrbacjava.web;

import com.github.h3yow.springsessionrbacjava.session.SessionManagementService;
import com.github.h3yow.springsessionrbacjava.session.SessionView;
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
 * 用户自助会话管理端点（位于 /api/user/**，要求有效会话 + USER 角色 + CSRF）：
 * <ul>
 *   <li>GET  /api/user/sessions：本人活跃会话列表（稳定排序，当前会话标记 current=true）；</li>
 *   <li>POST /api/user/sessions/{id}/revoke：定向下线本人指定会话；</li>
 *   <li>POST /api/user/sessions/revoke-others：一键下线除当前会话外的全部本人会话。</li>
 * </ul>
 * 归属不匹配/目标不存在一律 404 {"error":"NOT_FOUND"}，与既有"越权=资源不存在"约定一致，
 * 不泄露任何会话的存在性与归属。
 */
@RestController
public class SessionController {

    private final SessionManagementService sessionManagementService;

    public SessionController(SessionManagementService sessionManagementService) {
        this.sessionManagementService = sessionManagementService;
    }

    @GetMapping("/api/user/sessions")
    public Map<String, Object> list(HttpServletRequest request) {
        String username = (String) request.getAttribute(SessionInterceptor.ATTR_USERNAME);
        String currentSessionId = (String) request.getAttribute(SessionInterceptor.ATTR_SESSION_ID);
        List<SessionView> sessions = sessionManagementService.listSessions(username, currentSessionId);
        return Map.of("sessions", sessions);
    }

    @PostMapping("/api/user/sessions/revoke-others")
    public Map<String, Object> revokeOthers(HttpServletRequest request) {
        String username = (String) request.getAttribute(SessionInterceptor.ATTR_USERNAME);
        String currentSessionId = (String) request.getAttribute(SessionInterceptor.ATTR_SESSION_ID);
        int revoked = sessionManagementService.revokeOtherSessions(username, currentSessionId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "OK");
        body.put("revokedCount", revoked);
        return body;
    }

    @PostMapping("/api/user/sessions/{sessionId}/revoke")
    public ResponseEntity<Map<String, Object>> revokeOne(@PathVariable String sessionId,
                                                         HttpServletRequest request) {
        String username = (String) request.getAttribute(SessionInterceptor.ATTR_USERNAME);
        SessionManagementService.RevokeOutcome outcome =
                sessionManagementService.revokeSession(username, sessionId);
        if (outcome != SessionManagementService.RevokeOutcome.REVOKED) {
            return ResponseEntity.status(404).body(Map.of("error", "NOT_FOUND"));
        }
        return ResponseEntity.ok(Map.of("status", "OK"));
    }
}
