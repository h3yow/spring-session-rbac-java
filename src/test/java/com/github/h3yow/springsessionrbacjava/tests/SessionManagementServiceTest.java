package com.github.h3yow.springsessionrbacjava.tests;

import com.github.h3yow.springsessionrbacjava.session.SessionLookup;
import com.github.h3yow.springsessionrbacjava.session.SessionManagementService;
import com.github.h3yow.springsessionrbacjava.session.SessionRecord;
import com.github.h3yow.springsessionrbacjava.session.SessionStore;
import com.github.h3yow.springsessionrbacjava.session.SessionView;
import com.github.h3yow.springsessionrbacjava.session.TerminationReason;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 场景一/二的服务层测试：查看本人会话、定向下线、一键下线其他、
 * 名额立即释放与重新占用、跨账号绝不能互相操作。
 */
class SessionManagementServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SessionManagementServiceTest.class);

    @Test
    void listContainsOnlyOwnSessionsWithStableOrderAndCurrentMarked() {
        SessionStore store = new SessionStore();
        SessionManagementService svc = new SessionManagementService(store);
        SessionRecord a1 = store.create("alice", 3600, 5);
        SessionRecord b1 = store.create("bob", 3600, 5);   // 别人的会话，绝不能出现
        SessionRecord a2 = store.create("alice", 3600, 5);
        SessionRecord b2 = store.create("bob", 3600, 5);

        List<SessionView> views = svc.listSessions("alice", a2.id());
        log.info("alice sessions: {}", views.stream().map(SessionView::id).toList());
        assertEquals(2, views.size(), "列表只能包含本人会话，数量稳定");
        assertEquals(a1.id(), views.get(0).id(), "按创建时间升序");
        assertEquals(a2.id(), views.get(1).id());
        assertFalse(views.get(0).current());
        assertTrue(views.get(1).current(), "当前会话必须被标出");
        assertTrue(views.stream().noneMatch(v -> v.id().equals(b1.id()) || v.id().equals(b2.id())),
                "不能通过该入口感知任何其他人的会话");
        assertNotNull(views.get(0).createdAt());
        assertNotNull(views.get(0).lastActivityAt());

        // bob 反复登录/注销不影响 alice 列表的成员与顺序
        store.revoke(b1.id());
        store.create("bob", 3600, 5);
        List<SessionView> again = svc.listSessions("alice", a2.id());
        assertEquals(views, again, "其他人的活动不得抖动本人列表");
    }

    @Test
    void targetedRevokeTakesEffectImmediatelyAndFreesCap() {
        SessionStore store = new SessionStore();
        SessionManagementService svc = new SessionManagementService(store);
        SessionRecord a1 = store.create("alice", 3600, 2);
        SessionRecord a2 = store.create("alice", 3600, 2);
        assertEquals(2, store.activeCount("alice"));

        var outcome = svc.revokeSession("alice", a1.id());
        assertEquals(SessionManagementService.RevokeOutcome.REVOKED, outcome);
        assertEquals(1, store.activeCount("alice"), "名额必须立即释放");

        SessionLookup lookup = store.lookup(a1.id());
        assertEquals(SessionLookup.State.TERMINATED, lookup.state());
        assertEquals(TerminationReason.LOGOUT, lookup.reason(), "定向下线原因=主动注销");
        // 被下线客户端下次访问/续期不能继续操作
        assertEquals(SessionLookup.State.TERMINATED, store.renew(a1.id(), 3600).state());
        assertEquals(SessionLookup.State.ACTIVE, store.lookup(a2.id()).state(), "其他会话不受影响");

        // 释放的名额能立刻被重新占上
        SessionRecord a3 = store.create("alice", 3600, 2);
        assertEquals(2, store.activeCount("alice"));
        assertEquals(SessionLookup.State.ACTIVE, store.lookup(a2.id()).state());
        assertEquals(SessionLookup.State.ACTIVE, store.lookup(a3.id()).state());
        log.info("cap freed and reoccupied: a2 active, a3 active, a1 terminated");
    }

    @Test
    void revokeOthersKeepsCurrentAndRevokesRest() {
        SessionStore store = new SessionStore();
        SessionManagementService svc = new SessionManagementService(store);
        SessionRecord a1 = store.create("alice", 3600, 5);
        SessionRecord a2 = store.create("alice", 3600, 5);
        SessionRecord current = store.create("alice", 3600, 5);

        int revoked = svc.revokeOtherSessions("alice", current.id());
        assertEquals(2, revoked);
        assertEquals(1, store.activeCount("alice"));
        assertEquals(SessionLookup.State.ACTIVE, store.lookup(current.id()).state(), "当前会话必须保留");
        assertEquals(TerminationReason.LOGOUT, store.lookup(a1.id()).reason());
        assertEquals(TerminationReason.LOGOUT, store.lookup(a2.id()).reason());

        // 幂等：再次调用下线 0 个
        assertEquals(0, svc.revokeOtherSessions("alice", current.id()));
        log.info("revoke-others idempotent second call=0");
    }

    @Test
    void cannotTouchAnotherUsersSessions() {
        SessionStore store = new SessionStore();
        SessionManagementService svc = new SessionManagementService(store);
        SessionRecord alice = store.create("alice", 3600, 5);
        SessionRecord bob = store.create("bob", 3600, 5);

        // alice 试图下线 bob 的会话：结论与目标不存在完全一致
        var cross = svc.revokeSession("alice", bob.id());
        assertEquals(SessionManagementService.RevokeOutcome.NOT_OWNER_OR_ABSENT, cross);
        assertEquals(SessionLookup.State.ACTIVE, store.lookup(bob.id()).state(),
                "绝不能误伤别人的会话");
        var missing = svc.revokeSession("alice", "no-such-id");
        assertEquals(cross, missing, "越权下线与下线不存在目标返回一致，不泄露存在性/归属");

        // 一键下线他人会话：以 alice 身份调用不会影响 bob
        int n = store.revokeOthers("alice", bob.id());
        assertEquals(0, n, "keep 的会话不属于自己时不能下线任何会话");
        assertEquals(SessionLookup.State.ACTIVE, store.lookup(bob.id()).state());
        assertEquals(SessionLookup.State.ACTIVE, store.lookup(alice.id()).state());
    }
}
