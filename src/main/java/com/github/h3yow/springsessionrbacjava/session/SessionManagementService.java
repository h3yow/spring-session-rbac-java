package com.github.h3yow.springsessionrbacjava.session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 用户自助会话管理：只允许操作本人会话，所有归属校验在服务端完成。
 * 下线立即生效（活跃表移除、名额释放、写入带原因的墓碑），
 * 被下线客户端下次访问/续期会得到与原因一致的结论。
 */
@Service
public class SessionManagementService {

    private static final Logger log = LoggerFactory.getLogger(SessionManagementService.class);

    /** 下线操作结果：NOT_OWNER_OR_ABSENT 与"目标不存在"对调用方不可区分。 */
    public enum RevokeOutcome {
        REVOKED,
        NOT_OWNER_OR_ABSENT
    }

    private final SessionStore sessionStore;

    public SessionManagementService(SessionStore sessionStore) {
        this.sessionStore = sessionStore;
    }

    /** 当前用户自己的活跃会话，稳定数量/排序/字段，不受其他账号活动影响。 */
    public List<SessionView> listSessions(String username, String currentSessionId) {
        return sessionStore.listActive(username, currentSessionId);
    }

    /** 定向下线本人指定会话；目标不存在或不属于本人返回相同结论（不泄露存在性）。 */
    public RevokeOutcome revokeSession(String username, String targetSessionId) {
        boolean revoked = sessionStore.revokeOwned(username, targetSessionId);
        log.info("revoke session request: owner={}, target={}, outcome={}",
                username, targetSessionId, revoked ? "REVOKED" : "NOT_OWNER_OR_ABSENT");
        return revoked ? RevokeOutcome.REVOKED : RevokeOutcome.NOT_OWNER_OR_ABSENT;
    }

    /** 一键下线除当前会话外的全部本人会话，返回被下线数量（幂等：再次调用为 0）。 */
    public int revokeOtherSessions(String username, String currentSessionId) {
        return sessionStore.revokeOthers(username, currentSessionId);
    }
}
