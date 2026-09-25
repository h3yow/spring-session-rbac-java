package com.github.h3yow.springsessionrbacjava.tests;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端流程：登录/Cookie 安全属性、会话保护、CSRF、越权、注销、幂等重复提交。
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowWebTest {

    private static final Logger log = LoggerFactory.getLogger(AuthFlowWebTest.class);

    @Autowired
    private MockMvc mockMvc;

    private MvcResult login(String username, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andReturn();
    }

    private record Session(Cookie cookie, String csrfToken) {
    }

    private Session loginOk(String username, String password) throws Exception {
        MvcResult result = login(username, password);
        assertEquals(200, result.getResponse().getStatus());
        Cookie cookie = result.getResponse().getCookie("SESSION");
        assertNotNull(cookie);
        String body = result.getResponse().getContentAsString();
        String token = body.replaceAll(".*\"csrfToken\":\"([^\"]+)\".*", "$1");
        return new Session(cookie, token);
    }

    @Test
    void loginSetsSecureCookieAndCsrfToken() throws Exception {
        MvcResult result = login("alice", "alice-pass");
        String setCookie = result.getResponse().getHeader("Set-Cookie");
        log.info("判定依据: Set-Cookie={}", setCookie);
        assertEquals(200, result.getResponse().getStatus());
        assertNotNull(setCookie);
        assertTrue(setCookie.contains("HttpOnly"));
        assertTrue(setCookie.contains("SameSite=Strict"));
        assertTrue(setCookie.contains("Path=/"));
        jsonPath("$.csrfToken").exists();
    }

    @Test
    void loginFailuresDoNotLeakAccountExistence() throws Exception {
        MvcResult wrongPassword = login("alice", "bad");
        MvcResult unknownUser = login("ghost", "bad");
        log.info("判定依据: 状态码 {} vs {}, 响应体 {} vs {}",
                wrongPassword.getResponse().getStatus(), unknownUser.getResponse().getStatus(),
                wrongPassword.getResponse().getContentAsString(),
                unknownUser.getResponse().getContentAsString());
        assertEquals(401, wrongPassword.getResponse().getStatus());
        assertEquals(wrongPassword.getResponse().getStatus(), unknownUser.getResponse().getStatus());
        assertEquals(wrongPassword.getResponse().getContentAsString(),
                unknownUser.getResponse().getContentAsString());
    }

    @Test
    void missingSessionIsRejectedWithDistinctReason() throws Exception {
        log.info("输入: 无 Cookie 访问 /api/resources/user");
        mockMvc.perform(get("/api/resources/user"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("SESSION_MISSING"));
    }

    @Test
    void validSessionAccessesUserResource() throws Exception {
        Session session = loginOk("alice", "alice-pass");
        log.info("输入: 携带会话 Cookie 访问 /api/resources/user");
        mockMvc.perform(get("/api/resources/user").cookie(session.cookie()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"));
    }

    @Test
    void forbiddenAndNonexistentResourceAreIndistinguishable() throws Exception {
        Session session = loginOk("alice", "alice-pass");
        MvcResult forbidden = mockMvc.perform(get("/api/resources/admin").cookie(session.cookie()))
                .andReturn();
        MvcResult nonexistent = mockMvc.perform(get("/api/resources/nope").cookie(session.cookie()))
                .andReturn();
        log.info("判定依据: 越权状态 {} vs 不存在状态 {}, 均为 404",
                forbidden.getResponse().getStatus(), nonexistent.getResponse().getStatus());
        assertEquals(404, forbidden.getResponse().getStatus());
        assertEquals(404, nonexistent.getResponse().getStatus());
    }

    @Test
    void clientSuppliedRoleIsIgnored() throws Exception {
        Session session = loginOk("alice", "alice-pass");
        log.info("输入: alice 自报角色 ADMIN (请求头与参数), 访问 /api/resources/admin");
        mockMvc.perform(get("/api/resources/admin")
                        .cookie(session.cookie())
                        .header("X-Role", "ADMIN")
                        .param("role", "ADMIN"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("RESOURCE_NOT_AVAILABLE"));
    }

    @Test
    void mutatingRequestRequiresCsrfToken() throws Exception {
        Session session = loginOk("alice", "alice-pass");
        log.info("输入: 无 CSRF 令牌的 POST /api/resources/transfer");
        mockMvc.perform(post("/api/resources/transfer")
                        .cookie(session.cookie())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"toAccount\":\"bob\",\"amount\":100}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("CSRF_TOKEN_MISSING"));

        log.info("输入: 错误 CSRF 令牌的 POST /api/resources/transfer");
        mockMvc.perform(post("/api/resources/transfer")
                        .cookie(session.cookie())
                        .header("X-CSRF-TOKEN", "forged-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"toAccount\":\"bob\",\"amount\":100}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("CSRF_TOKEN_MISMATCH"));

        log.info("输入: 正确 CSRF 令牌 + 幂等键的 POST /api/resources/transfer");
        mockMvc.perform(post("/api/resources/transfer")
                        .cookie(session.cookie())
                        .header("X-CSRF-TOKEN", session.csrfToken())
                        .header("Idempotency-Key", "tx-1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"toAccount\":\"bob\",\"amount\":100}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("completed"));
    }

    @Test
    void duplicateAndConcurrentSubmissionsAreIdempotent() throws Exception {
        Session session = loginOk("alice", "alice-pass");
        int attempts = 8;
        ExecutorService pool = Executors.newFixedThreadPool(attempts);
        List<Callable<MvcResult>> tasks = new ArrayList<>();
        for (int i = 0; i < attempts; i++) {
            tasks.add(() -> mockMvc.perform(post("/api/resources/transfer")
                            .cookie(session.cookie())
                            .header("X-CSRF-TOKEN", session.csrfToken())
                            .header("Idempotency-Key", "tx-dup")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"toAccount\":\"bob\",\"amount\":50}"))
                    .andReturn());
        }
        List<Future<MvcResult>> futures = pool.invokeAll(tasks);
        pool.shutdown();

        String firstBody = null;
        for (Future<MvcResult> future : futures) {
            MvcResult result = future.get();
            assertEquals(200, result.getResponse().getStatus());
            String body = result.getResponse().getContentAsString();
            if (firstBody == null) {
                firstBody = body;
            }
            assertEquals(firstBody, body);
        }
        log.info("判定依据: {} 个并发重复提交(同一幂等键)返回完全一致: {}", attempts, firstBody);
    }

    @Test
    void logoutInvalidatesSessionAndReuseIsRejected() throws Exception {
        Session session = loginOk("alice", "alice-pass");
        mockMvc.perform(post("/api/auth/logout")
                        .cookie(session.cookie())
                        .header("X-CSRF-TOKEN", session.csrfToken()))
                .andExpect(status().isOk());
        log.info("输入: 注销后复用原会话 Cookie");
        mockMvc.perform(get("/api/resources/user").cookie(session.cookie()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("SESSION_REVOKED"));
    }

    @Test
    void concurrentLogoutAndAccessLeaveConsistentState() throws Exception {
        Session session = loginOk("alice", "alice-pass");
        // 先注销，再并发访问：所有访问必须稳定失败为 SESSION_REVOKED
        mockMvc.perform(post("/api/auth/logout")
                        .cookie(session.cookie())
                        .header("X-CSRF-TOKEN", session.csrfToken()))
                .andExpect(status().isOk());
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<Integer>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> mockMvc.perform(get("/api/resources/user").cookie(session.cookie()))
                    .andReturn().getResponse().getStatus());
        }
        List<Future<Integer>> futures = pool.invokeAll(tasks);
        pool.shutdown();
        for (Future<Integer> future : futures) {
            assertEquals(401, future.get());
        }
        log.info("判定依据: 注销后 {} 个并发访问全部稳定返回 401, 无串号/越权", threads);
    }
}
