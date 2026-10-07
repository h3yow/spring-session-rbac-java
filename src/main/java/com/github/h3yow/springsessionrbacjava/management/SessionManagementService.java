package com.github.h3yow.springsessionrbacjava.management;

import com.github.h3yow.springsessionrbacjava.session.RevocationReason;
import com.github.h3yow.springsessionrbacjava.session.SessionRecord;
import com.github.h3yow.springsessionrbacjava.session.SessionStore;
import com.github.h3yow.springsessionrbacjava.session.SessionView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 用户自助会话管理：查看自己的活跃会话、定向下线、一键下线其他会话。
 * <ul>
 *   <li>所有数据范围严格限定为当前账号，列表只来自该账号自己的活跃会话；</li>
 *   <li>下线立即生效并释放并发名额（墓碑只承担"原因可分辨"，不占名额）；</li>
 *   <li>对他人/不存在会话的操作统一返回 NOT_FOUND，不泄露目标存在性或归属。</li>
 * </ul>
 */
@Service
public class SessionManagementService {

    private static final Logger log = LoggerFactory.getLogger(SessionManagementService.class);

    private final SessionStore sessionStore;

    public SessionManagementService(SessionStore sessionStore) {
        this.sessionStore = sessionStore;
    }

    /** 列出该用户全部活跃会话（稳定字段、稳定排序），currentSessionId 对应项标 current=true。 */
    public List<SessionView> listSessions(String username, String currentSessionId) {
        List<SessionView> views = sessionStore.listActive(username).stream()
                .map(r -> toView(r, r.id().equals(currentSessionId)))
                .toList();
        log.info("list sessions: username={}, count={}, current={}", username, views.size(), currentSessionId);
        return views;
    }

    /**
     * 定向下线属于该用户的指定会话。
     * 不属于该用户或不存在均返回 NOT_FOUND（对外不可区分）；
     * 幂等：目标已是本人墓碑也返回 REVOKED，不覆盖首次下线原因。
     */
    public TerminateStatus terminate(String username, String targetSessionId) {
        SessionStore.OwnedRevokeResult result = sessionStore.revokeIfOwner(
                username, targetSessionId, RevocationReason.USER_TERMINATED);
        log.info("terminate: username={}, target={}, result={}", username, targetSessionId, result);
        return result == SessionStore.OwnedRevokeResult.REVOKED
                ? TerminateStatus.REVOKED : TerminateStatus.NOT_FOUND;
    }

    /** 下线除当前会话外的全部其他活跃会话，返回实际新下线数量（当前会话永不受影响）。 */
    public int terminateOthers(String username, String currentSessionId) {
        int n = sessionStore.revokeOthers(username, currentSessionId, RevocationReason.USER_TERMINATED);
        log.info("terminate others: username={}, keep={}, newlyRevoked={}", username, currentSessionId, n);
        return n;
    }

    private static SessionView toView(SessionRecord r, boolean current) {
        return new SessionView(r.id(), r.createdAt(), r.lastAccessAt(), r.expiresAt(), current);
    }
}
