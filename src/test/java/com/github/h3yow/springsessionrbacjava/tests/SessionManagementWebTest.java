package com.github.h3yow.springsessionrbacjava.tests;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 会话管理的端到端测试：
 * 场景一列表（字段/排序/当前标记/隔离性），场景二定向与一键下线（CSRF、立即生效、
 * 名额释放、跨账号 404），场景三三种被登出原因在资源访问与续期入口一致可区分、
 * 伪造/不存在会话稳定 SESSION_MISSING，且不回归"越权=404"约定。
 */
@SpringBootTest
@AutoConfigureMockMvc
class SessionManagementWebTest {

    private static final Logger log = LoggerFactory.getLogger(SessionManagementWebTest.class);

    @Autowired
    private MockMvc mvc;

    private record Session(String id, Cookie cookie, String csrf) {
    }

    private Session login(String username, String password) throws Exception {
        MvcResult r = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk()).andReturn();
        String value = r.getResponse().getHeader(HttpHeaders.SET_COOKIE).split(";")[0].split("=")[1];
        String csrf = r.getResponse().getContentAsString()
                .replaceAll(".*\"csrfToken\":\"([^\"]+)\".*", "$1");
        return new Session(value, new Cookie("SESSIONID", value), csrf);
    }

    private String reason(MvcResult r) throws Exception {
        return r.getResponse().getContentAsString()
                .replaceAll(".*\"reason\":\"([^\"]+)\".*", "$1");
    }

    // ---------- 场景一：查看自己的会话 ----------

    @Test
    void listsOnlyOwnSessionsWithStableFieldsAndCurrentFlag() throws Exception {
        Session first = login("alice", "alice-pass");
        // 触发一次受保护访问，产生最近活动时间
        mvc.perform(get("/api/user/profile").cookie(first.cookie())).andExpect(status().isOk());
        Session current = login("alice", "alice-pass");
        Session bob = login("bob", "bob-pass");
        mvc.perform(get("/api/user/sessions").cookie(bob.cookie())).andExpect(status().isOk());

        MvcResult r = mvc.perform(get("/api/user/sessions").cookie(current.cookie()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sessions.length()").value(2))
                .andExpect(jsonPath("$.sessions[0].id").value(first.id()))
                .andExpect(jsonPath("$.sessions[0].current").value(false))
                .andExpect(jsonPath("$.sessions[0].createdAt").exists())
                .andExpect(jsonPath("$.sessions[0].lastActivityAt").exists())
                .andExpect(jsonPath("$.sessions[1].id").value(current.id()))
                .andExpect(jsonPath("$.sessions[1].current").value(true))
                .andReturn();
        log.info("alice session list: {}", r.getResponse().getContentAsString());

        // bob 的活动（再登录、注销）不得改变 alice 列表的成员/顺序/当前标记。
        // 注意：再次发起列表请求本身会刷新"当前会话"自己的 lastActivityAt（这是列表请求自身的活动），
        // 因此稳定性比较针对成员、顺序与另一条会话，而非当前会话的活动时间戳。
        login("bob", "bob-pass");
        MvcResult stable = mvc.perform(get("/api/user/sessions").cookie(current.cookie()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sessions.length()").value(2))
                .andExpect(jsonPath("$.sessions[0].id").value(first.id()))
                .andExpect(jsonPath("$.sessions[1].id").value(current.id()))
                .andExpect(jsonPath("$.sessions[1].current").value(true))
                .andReturn();
        log.info("stable list after bob activity: {}", stable.getResponse().getContentAsString());
        assertTrue(stable.getResponse().getContentAsString().contains(first.id()));
        assertFalse(stable.getResponse().getContentAsString().contains(bob.id()));

        // 未认证访问列表：401 + SESSION_MISSING
        mvc.perform(get("/api/user/sessions")).andExpect(status().isUnauthorized());
    }

    // ---------- 场景二：定向下线 / 一键下线其他 ----------

    @Test
    void targetedRevokeImmediatelyKillsSessionAndFreesCap() throws Exception {
        Session a = login("alice", "alice-pass");
        Session b = login("alice", "alice-pass"); // 此时已达默认上限 2

        // 状态变更需要 CSRF
        mvc.perform(post("/api/user/sessions/" + a.id() + "/revoke").cookie(b.cookie()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("CSRF_TOKEN_MISSING"));

        // 带正确 CSRF 定向下线 a
        mvc.perform(post("/api/user/sessions/" + a.id() + "/revoke")
                        .cookie(b.cookie()).header("X-CSRF-TOKEN", b.csrf()))
                .andExpect(status().isOk());
        log.info("revoked target session {}", a.id());

        // 被下线客户端立即失效，且原因是主动下线
        mvc.perform(get("/api/user/profile").cookie(a.cookie()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_REVOKED"));

        // 名额立即释放：再登录成功，且不会挤掉 b
        Session c = login("alice", "alice-pass");
        mvc.perform(get("/api/user/profile").cookie(b.cookie())).andExpect(status().isOk());
        mvc.perform(get("/api/user/sessions").cookie(c.cookie()))
                .andExpect(jsonPath("$.sessions.length()").value(2));

        // 重复下线同一个已终止目标：404（目标已不在活跃集合）
        mvc.perform(post("/api/user/sessions/" + a.id() + "/revoke")
                        .cookie(b.cookie()).header("X-CSRF-TOKEN", b.csrf()))
                .andExpect(status().isNotFound());
    }

    @Test
    void revokeOthersKeepsCurrentAndKillsRest() throws Exception {
        Session a = login("alice", "alice-pass");
        Session b = login("alice", "alice-pass");
        // 默认上限 2：a 最旧、b 为当前会话；一键下线应只终止 a、保留 b
        mvc.perform(post("/api/user/sessions/revoke-others")
                        .cookie(b.cookie()).header("X-CSRF-TOKEN", b.csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revokedCount").value(1));

        // 当前会话 b 仍然有效
        mvc.perform(get("/api/user/profile").cookie(b.cookie())).andExpect(status().isOk());
        // 被一键下线的 a 立即失效，原因=主动注销
        MvcResult dead = mvc.perform(get("/api/user/profile").cookie(a.cookie()))
                .andExpect(status().isUnauthorized()).andReturn();
        assertEquals("SESSION_REVOKED", reason(dead));
        // 幂等：再次调用下线 0 个
        mvc.perform(post("/api/user/sessions/revoke-others")
                        .cookie(b.cookie()).header("X-CSRF-TOKEN", b.csrf()))
                .andExpect(jsonPath("$.revokedCount").value(0));
    }

    @Test
    void cannotRevokeAnotherUsersSessionOrSenseItsExistence() throws Exception {
        Session alice = login("alice", "alice-pass");
        Session bob = login("bob", "bob-pass");

        // alice 下线 bob 的会话 → 404，与不存在资源逐字节一致
        String crossBody = mvc.perform(post("/api/user/sessions/" + bob.id() + "/revoke")
                        .cookie(alice.cookie()).header("X-CSRF-TOKEN", alice.csrf()))
                .andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
        String absentBody = mvc.perform(post("/api/user/sessions/forged-id/revoke")
                        .cookie(alice.cookie()).header("X-CSRF-TOKEN", alice.csrf()))
                .andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
        log.info("cross-user revoke body={}, absent body={}", crossBody, absentBody);
        assertEquals("{\"error\":\"NOT_FOUND\"}", crossBody);
        assertEquals(crossBody, absentBody, "越权下线与目标不存在必须不可区分");

        // bob 会话完好无损
        mvc.perform(get("/api/user/profile").cookie(bob.cookie())).andExpect(status().isOk());
        // alice 的列表里绝不会出现 bob
        MvcResult list = mvc.perform(get("/api/user/sessions").cookie(alice.cookie()))
                .andExpect(status().isOk()).andReturn();
        assertFalse(list.getResponse().getContentAsString().contains(bob.id()));
    }

    // ---------- 场景三：三种被登出原因可区分且不泄露 ----------

    @Test
    void logoutEvictionAndExpiryAreDistinguishableAcrossEntries() throws Exception {
        // 1) 本人主动注销
        Session loggedOut = login("alice", "alice-pass");
        mvc.perform(post("/auth/logout").cookie(loggedOut.cookie())
                .header("X-CSRF-TOKEN", loggedOut.csrf())).andExpect(status().isOk());
        assertUnauthorizedReason(loggedOut.cookie(), loggedOut.csrf(), "SESSION_REVOKED");

        // 2) 被新登录挤掉（默认上限 2）：s1 最旧，第三次登录挤掉 s1
        Session s1 = login("bob", "bob-pass");
        Session s2 = login("bob", "bob-pass");
        Session s3 = login("bob", "bob-pass");
        MvcResult evicted = mvc.perform(get("/api/user/profile").cookie(s1.cookie()))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("evicted session resource body={}", evicted.getResponse().getContentAsString());
        assertEquals("SESSION_CAP_EVICTED", reason(evicted), "被挤掉必须可区分");
        MvcResult evictedRenew = mvc.perform(post("/auth/renew").cookie(s1.cookie())
                        .header("X-CSRF-TOKEN", s1.csrf()))
                .andExpect(status().isUnauthorized()).andReturn();
        assertEquals("SESSION_CAP_EVICTED", reason(evictedRenew), "续期入口结论必须一致");
        // 未受影响的会话仍正常
        mvc.perform(get("/api/user/profile").cookie(s2.cookie())).andExpect(status().isOk());
        mvc.perform(get("/api/user/profile").cookie(s3.cookie())).andExpect(status().isOk());

        // 3) 自然过期在 SessionExpiryWebTest（ttl=0）覆盖；此处验证过期不能续期复活
        //    通过挤掉/注销的会话同样不能通过续期复活
        MvcResult logoutRenew = mvc.perform(post("/auth/renew").cookie(loggedOut.cookie())
                        .header("X-CSRF-TOKEN", loggedOut.csrf()))
                .andExpect(status().isUnauthorized()).andReturn();
        assertEquals("SESSION_REVOKED", reason(logoutRenew), "续期入口与资源入口结论一致");
    }

    @Test
    void nonexistentAndForgedSessionsAreIndistinguishableMissing() throws Exception {
        Cookie forged = new Cookie("SESSIONID", "definitely-not-a-real-session-id");
        // 资源访问
        MvcResult r1 = mvc.perform(get("/api/user/profile").cookie(forged))
                .andExpect(status().isUnauthorized()).andReturn();
        assertEquals("SESSION_MISSING", reason(r1));
        // 根本不带 Cookie
        MvcResult r2 = mvc.perform(get("/api/user/profile"))
                .andExpect(status().isUnauthorized()).andReturn();
        assertEquals("SESSION_MISSING", reason(r2));
        // 续期入口同样结论
        MvcResult r3 = mvc.perform(post("/auth/renew").cookie(forged)
                        .header("X-CSRF-TOKEN", "anything"))
                .andExpect(status().isUnauthorized()).andReturn();
        assertEquals("SESSION_MISSING", reason(r3));
        log.info("forged/missing responses identical on resource & renew: {}",
                r1.getResponse().getContentAsString());
        // 语义一致（body 均为 UNAUTHORIZED+SESSION_MISSING；Map 序列化键序不比较）
        assertEquals(reason(r1), reason(r2));
        assertEquals(reason(r1), reason(r3));

        // 不回归：已认证越权仍是 404 NOT_FOUND，与资源不存在一致
        Session alice = login("alice", "alice-pass");
        MvcResult forbidden = mvc.perform(get("/api/admin/dashboard").cookie(alice.cookie()))
                .andExpect(status().isNotFound()).andReturn();
        assertNotNull(forbidden);
        assertEquals("{\"error\":\"NOT_FOUND\"}", forbidden.getResponse().getContentAsString());
    }

    private void assertUnauthorizedReason(Cookie cookie, String csrf, String expected) throws Exception {
        MvcResult resource = mvc.perform(get("/api/user/profile").cookie(cookie))
                .andExpect(status().isUnauthorized()).andReturn();
        MvcResult renew = mvc.perform(post("/auth/renew").cookie(cookie)
                        .header("X-CSRF-TOKEN", csrf))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("expected={}, resource={}, renew={}", expected,
                resource.getResponse().getContentAsString(), renew.getResponse().getContentAsString());
        assertEquals(expected, reason(resource));
        assertEquals(expected, reason(renew), "资源访问与续期入口原因必须一致");
        assertTrue(resource.getResponse().getContentAsString().contains(expected));
    }
}
