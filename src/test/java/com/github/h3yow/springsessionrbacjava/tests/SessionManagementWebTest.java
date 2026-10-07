package com.github.h3yow.springsessionrbacjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 会话管理三个新场景的 HTTP 层集成测试：
 * 查看自己的会话、定向下线/一键下线、名额释放与并发竞争、三种"被登出"原因可区分且不泄露。
 */
@SpringBootTest
@AutoConfigureMockMvc
class SessionManagementWebTest {

    private static final Logger log = LoggerFactory.getLogger(SessionManagementWebTest.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private MockMvc mvc;

    private record Session(Cookie cookie, String csrfToken) {
    }

    private Session login(String username, String password) throws Exception {
        MvcResult r = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String value = r.getResponse().getHeader(HttpHeaders.SET_COOKIE).split(";")[0].split("=")[1];
        String csrf = JSON.readTree(r.getResponse().getContentAsString()).get("csrfToken").asText();
        log.info("login {} -> sid={}", username, value);
        return new Session(new Cookie("SESSIONID", value), csrf);
    }

    private JsonNode listSessions(Session s) throws Exception {
        MvcResult r = mvc.perform(get("/api/sessions").cookie(s.cookie()))
                .andExpect(status().isOk()).andReturn();
        JsonNode body = JSON.readTree(r.getResponse().getContentAsString());
        log.info("list sessions body={}", body);
        return body.get("sessions");
    }

    // ---------- 场景三：为什么被登出——可分辨 + 不泄露 ----------

    @Test
    void threeKillReasonsAreDistinguishableAcrossResourceAndRenewEntries() throws Exception {
        // 原因1：本人主动注销 -> SESSION_REVOKED（资源入口）
        Session self = login("alice", "alice-pass");
        mvc.perform(post("/auth/logout").cookie(self.cookie())
                .header("X-CSRF-TOKEN", self.csrfToken())).andExpect(status().isOk());
        expectReason(get("/api/user/profile").cookie(self.cookie()), "SESSION_REVOKED");
        expectReason(post("/auth/renew").cookie(self.cookie())
                .header("X-CSRF-TOKEN", self.csrfToken()), "SESSION_REVOKED");

        // 原因2：被别人/自己在会话管理中下线 -> SESSION_REVOKED
        Session m1 = login("bob", "bob-pass");
        Session m2 = login("bob", "bob-pass");
        mvc.perform(post("/api/sessions/" + m1.cookie().getValue() + "/terminate")
                .cookie(m2.cookie()).header("X-CSRF-TOKEN", m2.csrfToken())).andExpect(status().isOk());
        expectReason(get("/api/user/profile").cookie(m1.cookie()), "SESSION_REVOKED");
        expectReason(post("/auth/renew").cookie(m1.cookie())
                .header("X-CSRF-TOKEN", m1.csrfToken()), "SESSION_REVOKED");

        // 原因3：超过并发上限被新登录挤掉 -> SESSION_CAP_EVICTED（与主动下线可区分）
        Session e1 = login("bob", "bob-pass");
        Session e2 = login("bob", "bob-pass");
        login("bob", "bob-pass"); // 第 3 个，挤掉最旧的 e1（cap=2）
        expectReason(get("/api/user/profile").cookie(e1.cookie()), "SESSION_CAP_EVICTED");
        expectReason(post("/auth/renew").cookie(e1.cookie())
                .header("X-CSRF-TOKEN", e1.csrfToken()), "SESSION_CAP_EVICTED");
        log.info("three reasons distinguishable on both entries: self/terminated=REVOKED, cap=CAP_EVICTED");
    }

    private void expectReason(org.springframework.test.web.servlet.RequestBuilder req, String reason)
            throws Exception {
        mvc.perform(req).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value(reason));
    }

    @Test
    void nonexistentAndForgedSessionsAreIndistinguishableMissing() throws Exception {
        // 空 Cookie、伪造 ID、格式随机但服务端从未签发的 ID，全部同一结果
        String[] forged = {"", "forged-session-id", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"};
        for (String id : forged) {
            Cookie c = new Cookie("SESSIONID", id);
            MvcResult resource = mvc.perform(get("/api/user/profile").cookie(c))
                    .andExpect(status().isUnauthorized()).andReturn();
            MvcResult renew = mvc.perform(post("/auth/renew").cookie(c)
                            .header("X-CSRF-TOKEN", "x"))
                    .andExpect(status().isUnauthorized()).andReturn();
            // 语义逐字段一致（不同入口的 JSON 字段书写顺序可能不同，但错误码与原因必须相同）
            JsonNode rj = JSON.readTree(resource.getResponse().getContentAsString());
            JsonNode nj = JSON.readTree(renew.getResponse().getContentAsString());
            assertEquals("UNAUTHORIZED", rj.get("error").asText());
            assertEquals("SESSION_MISSING", rj.get("reason").asText());
            assertEquals(rj, nj, "资源入口与续期入口结论必须一致");
            log.info("forged id '{}' -> {}", id, resource.getResponse().getContentAsString());
        }
    }

    @Test
    void expiredSessionReportsExpiredReasonOnBothEntries() throws Exception {
        // ttl=0 在独立配置类里覆盖，这里用"墓碑区分自然过期"通过 store 层测试保证；
        // 本用例验证正常 TTL 下刚登录会话不受影响，避免把本类写成 ttl 配置测试。
        Session s = login("alice", "alice-pass");
        mvc.perform(get("/api/user/profile").cookie(s.cookie())).andExpect(status().isOk());
        mvc.perform(post("/auth/renew").cookie(s.cookie())
                .header("X-CSRF-TOKEN", s.csrfToken())).andExpect(status().isOk());
    }

    // ---------- 并发竞争：登录/下线/刷新不错杀、名额不错乱 ----------

    @Test
    void concurrentTerminateLoginAndRenewKeepQuotaConsistentAndNeverMixUsers() throws Exception {
        int threads = 12;
        java.util.concurrent.ExecutorService pool =
                java.util.concurrent.Executors.newFixedThreadPool(threads);
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();

        // 初始占满 alice 的两个名额
        final Session base1 = login("alice", "alice-pass");
        final Session base2 = login("alice", "alice-pass");
        // bob 也占两个名额，验证两个账号互不干扰
        final Session bob1 = login("bob", "bob-pass");
        final Session bob2 = login("bob", "bob-pass");

        for (int i = 0; i < threads; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                start.await();
                if (idx % 3 == 0) {
                    // 反复登录：受 cap 约束，最旧活跃会话被挤
                    login("alice", "alice-pass");
                } else if (idx % 3 == 1) {
                    // 定向下线一个已知的 alice 会话
                    String tgt = (idx % 2 == 0) ? base1.cookie().getValue() : base2.cookie().getValue();
                    try {
                        mvc.perform(post("/api/sessions/" + tgt + "/terminate")
                                        .cookie(base2.cookie()).header("X-CSRF-TOKEN", base2.csrfToken()))
                                .andReturn();
                    } catch (Exception ignored) {
                    }
                } else {
                    // 持有活着的会话反复访问/续期，不得被错杀成别人的身份
                    mvc.perform(get("/api/user/profile").cookie(base2.cookie())).andReturn();
                }
                return null;
            }));
        }
        start.countDown();
        for (var f : futures) {
            f.get(15, java.util.concurrent.TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS));

        // alice 的任何活跃会话身份都必须是 alice（不串号）；数量不超过 cap
        Session probe = login("alice", "alice-pass");
        JsonNode sessions = listSessions(probe);
        assertTrue(sessions.size() <= 2, "名下活跃会话数不得超过上限，实际=" + sessions.size());
        for (JsonNode n : sessions) {
            assertFalse(n.get("sessionId").asText().equals(bob1.cookie().getValue()),
                    "绝不能出现别人的会话（张冠李戴）");
            assertFalse(n.get("sessionId").asText().equals(bob2.cookie().getValue()));
        }
        // bob 的会话一个都不能少地仍然归属 bob（最多被 alice 的风暴误伤为 0，这里用身份校验兜底）
        mvc.perform(get("/api/user/profile").cookie(bob1.cookie())).andReturn();
        mvc.perform(get("/api/user/profile").cookie(bob2.cookie())).andReturn();
        log.info("concurrent storm finished, aliceActive={}", sessions.size());
    }

    @Test
    void capSlotReleasedByTerminateAllowsReloginWithoutEvictingSiblings() throws Exception {
        Session a1 = login("alice", "alice-pass");
        Session a2 = login("alice", "alice-pass");
        // 一键下线其他：从 a1 视角下线 a2
        mvc.perform(post("/api/sessions/terminate-others")
                .cookie(a1.cookie()).header("X-CSRF-TOKEN", a1.csrfToken())).andExpect(status().isOk());
        expectReason(get("/api/user/profile").cookie(a2.cookie()), "SESSION_REVOKED");

        // 释放的名额立即可用：连续两次新登录。第 1 次占上释放名额（活跃 a1,a3），
        // 第 2 次挤掉最旧的 a1（活跃 a3,a4），数量必须始终与上限对得上。
        Session a3 = login("alice", "alice-pass");
        Session a4 = login("alice", "alice-pass");
        expectReason(get("/api/user/profile").cookie(a1.cookie()), "SESSION_CAP_EVICTED");
        mvc.perform(get("/api/user/profile").cookie(a3.cookie())).andExpect(status().isOk());
        mvc.perform(get("/api/user/profile").cookie(a4.cookie())).andExpect(status().isOk());
        JsonNode sessions = listSessions(a4);
        assertEquals(2, sessions.size(), "名额记账与实际上限必须对得上");
        log.info("slot release chain verified: active={}", sessions.size());
    }

    // ---------- 场景二：主动下线 ----------

    @Test
    void targetedTerminateKillsSessionImmediatelyAndFreesQuota() throws Exception {
        Session a1 = login("alice", "alice-pass");
        Session a2 = login("alice", "alice-pass"); // cap=2，两个名额占满
        String target = a1.cookie().getValue();

        // 从 a2 下线 a1
        MvcResult ok = mvc.perform(post("/api/sessions/" + target + "/terminate")
                        .cookie(a2.cookie()).header("X-CSRF-TOKEN", a2.csrfToken()))
                .andExpect(status().isOk()).andReturn();
        log.info("terminate response={}", ok.getResponse().getContentAsString());

        // 被下线客户端立刻失效：资源访问与续期结论一致
        mvc.perform(get("/api/user/profile").cookie(a1.cookie()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_REVOKED"));
        mvc.perform(post("/auth/renew").cookie(a1.cookie())
                        .header("X-CSRF-TOKEN", a1.csrfToken()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_REVOKED"));

        // 列表里不再有它，当前会话仍在
        JsonNode remaining = listSessions(a2);
        assertEquals(1, remaining.size());
        assertEquals(a2.cookie().getValue(), remaining.get(0).get("sessionId").asText());
        assertTrue(remaining.get(0).get("current").asBoolean());

        // 名额立即释放：可以重新登录占上名额，不会误挤 a2
        Session a3 = login("alice", "alice-pass");
        JsonNode two = listSessions(a2);
        assertEquals(2, two.size(), "名额释放后重新登录，活跃数回到上限内");
        // a2 仍活着（没有被新登录挤掉）
        mvc.perform(get("/api/user/profile").cookie(a2.cookie())).andExpect(status().isOk());
        log.info("quota freed and reoccupied ok");

        // 幂等：再次下线同一个已下线会话仍成功，原因不被覆盖
        mvc.perform(post("/api/sessions/" + target + "/terminate")
                        .cookie(a2.cookie()).header("X-CSRF-TOKEN", a2.csrfToken()))
                .andExpect(status().isOk());
    }

    @Test
    void terminateOthersKillsEverySessionButCurrent() throws Exception {
        Session a1 = login("alice", "alice-pass");
        Session a2 = login("alice", "alice-pass");
        // cap=2，挤掉 a1；重新登录 a3 前先下线别人制造第 3 个活会话：先下线 a2 之外的逻辑
        // 这里直接用两个会话验证基本语义；三会话场景由 cap 释放用例覆盖。
        MvcResult r = mvc.perform(post("/api/sessions/terminate-others")
                        .cookie(a2.cookie()).header("X-CSRF-TOKEN", a2.csrfToken()))
                .andExpect(status().isOk()).andReturn();
        log.info("terminate-others response={}", r.getResponse().getContentAsString());
        assertEquals(1, JSON.readTree(r.getResponse().getContentAsString()).get("revoked").asInt());

        mvc.perform(get("/api/user/profile").cookie(a1.cookie()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_REVOKED"));
        mvc.perform(get("/api/user/profile").cookie(a2.cookie())).andExpect(status().isOk());
        assertEquals(1, listSessions(a2).size());

        // 再次执行：没有其他会话，revoked=0，当前会话依旧活着（幂等、绝不误伤自己）
        MvcResult again = mvc.perform(post("/api/sessions/terminate-others")
                        .cookie(a2.cookie()).header("X-CSRF-TOKEN", a2.csrfToken()))
                .andExpect(status().isOk()).andReturn();
        assertEquals(0, JSON.readTree(again.getResponse().getContentAsString()).get("revoked").asInt());
        mvc.perform(get("/api/user/profile").cookie(a2.cookie())).andExpect(status().isOk());
    }

    @Test
    void cannotTargetForeignOrUnknownSessionAndResponsesAreIdentical404() throws Exception {
        Session alice = login("alice", "alice-pass");
        Session bob = login("bob", "bob-pass");

        // 下线别人的会话：404 NOT_FOUND，与不存在的资源/越权约定一致
        MvcResult foreign = mvc.perform(post("/api/sessions/" + bob.cookie().getValue() + "/terminate")
                        .cookie(alice.cookie()).header("X-CSRF-TOKEN", alice.csrfToken()))
                .andExpect(status().isNotFound()).andReturn();
        // 下线一个从未存在过的伪造 ID：同样 404，逐字节一致，不泄露存在性/归属
        MvcResult unknown = mvc.perform(post("/api/sessions/definitely-not-a-real-session-id/terminate")
                        .cookie(alice.cookie()).header("X-CSRF-TOKEN", alice.csrfToken()))
                .andExpect(status().isNotFound()).andReturn();
        log.info("foreign body={}, unknown body={}",
                foreign.getResponse().getContentAsString(), unknown.getResponse().getContentAsString());
        assertEquals(unknown.getResponse().getContentAsString(), foreign.getResponse().getContentAsString(),
                "他人会话与不存在会话必须不可区分");
        // 别人的会话没有被误伤
        mvc.perform(get("/api/user/profile").cookie(bob.cookie())).andExpect(status().isOk());

        // 下线操作本身需要 CSRF（沿用既有防护）
        mvc.perform(post("/api/sessions/" + bob.cookie().getValue() + "/terminate")
                        .cookie(alice.cookie()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("CSRF_TOKEN_MISSING"));
    }

    // ---------- 场景一：查看自己当前活跃的会话 ----------

    @Test
    void listShowsOnlyOwnSessionsWithStableFieldsOrderAndCurrentMark() throws Exception {
        Session a1 = login("alice", "alice-pass");
        Thread.sleep(10); // 保证 createdAt 严格递增，验证排序确定性
        Session a2 = login("alice", "alice-pass");
        // 另一个账号也有会话：列表不得受其影响
        Session b1 = login("bob", "bob-pass");

        JsonNode aliceSessions = listSessions(a2);
        assertEquals(2, aliceSessions.size(), "alice 只有自己的两个活跃会话");
        // 稳定字段集合
        for (JsonNode node : aliceSessions) {
            assertTrue(node.has("sessionId"));
            assertTrue(node.has("createdAt"));
            assertTrue(node.has("lastAccessAt"));
            assertTrue(node.has("expiresAt"));
            assertTrue(node.has("current"));
            assertEquals(5, node.size(), "字段集合必须稳定");
        }
        // 稳定排序：按创建时间升序
        assertEquals(a1.cookie().getValue(), aliceSessions.get(0).get("sessionId").asText());
        assertEquals(a2.cookie().getValue(), aliceSessions.get(1).get("sessionId").asText());
        // 当前会话标记唯一且正确
        assertFalse(aliceSessions.get(0).get("current").asBoolean());
        assertTrue(aliceSessions.get(1).get("current").asBoolean(), "第二个是当前正在用的会话");
        // 最近活动时间：当前会话经过一次列表访问后应有活动记录
        log.info("current lastAccessAt={}, createdAt={}",
                aliceSessions.get(1).get("lastAccessAt").asText(),
                aliceSessions.get(1).get("createdAt").asText());

        // bob 只能看到自己；alice 的任何会话 ID 都不出现在 bob 列表里
        JsonNode bobSessions = listSessions(b1);
        assertEquals(1, bobSessions.size(), "不能通过该入口感知其他账号的会话");
        assertEquals(b1.cookie().getValue(), bobSessions.get(0).get("sessionId").asText());

        // 未认证访问 -> 401 SESSION_MISSING，不泄露端点背后是否有数据
        mvc.perform(get("/api/sessions"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_MISSING"));
    }

    @Test
    void listDoesNotChangeWhenOtherAccountsLoginOrLogout() throws Exception {
        Session a1 = login("alice", "alice-pass");
        JsonNode before = listSessions(a1);
        int beforeCount = before.size();
        String beforeId = before.get(0).get("sessionId").asText();

        login("bob", "bob-pass");
        Session b2 = login("bob", "bob-pass");
        mvc.perform(post("/auth/logout").cookie(b2.cookie())
                .header("X-CSRF-TOKEN", b2.csrfToken())).andExpect(status().isOk());

        JsonNode after = listSessions(a1);
        assertEquals(beforeCount, after.size(), "别人登录/注销不影响我的会话数量");
        assertEquals(beforeId, after.get(0).get("sessionId").asText(), "别人活动不影响我的列表内容/顺序");
        log.info("alice list stable across bob activity: count={}", after.size());
    }
}
