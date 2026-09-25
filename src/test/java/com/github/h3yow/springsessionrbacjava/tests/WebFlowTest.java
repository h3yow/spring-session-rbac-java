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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class WebFlowTest {

    private static final Logger log = LoggerFactory.getLogger(WebFlowTest.class);

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
        String setCookie = r.getResponse().getHeader(HttpHeaders.SET_COOKIE);
        log.info("login {}: Set-Cookie={}", username, setCookie);
        assertNotNull(setCookie);
        assertTrue(setCookie.contains("HttpOnly"), "Cookie 必须 HttpOnly");
        assertTrue(setCookie.contains("SameSite=Strict"), "Cookie 必须 SameSite=Strict");
        String value = setCookie.split(";")[0].split("=")[1];
        String csrf = r.getResponse().getContentAsString()
                .replaceAll(".*\"csrfToken\":\"([^\"]+)\".*", "$1");
        return new Session(new Cookie("SESSIONID", value), csrf);
    }

    @Test
    void fullLifecycleAcrossClientEntries() throws Exception {
        Session s = login("alice", "alice-pass");

        // 入口1：受保护资源 GET
        mvc.perform(get("/api/user/profile").cookie(s.cookie()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"));

        // 入口2：续期
        mvc.perform(post("/auth/renew").cookie(s.cookie())
                        .header("X-CSRF-TOKEN", s.csrfToken()))
                .andExpect(status().isOk());

        // 入口3：whoami 同一会话一致身份
        mvc.perform(get("/auth/whoami").cookie(s.cookie()))
                .andExpect(jsonPath("$.username").value("alice"));

        // 注销后所有入口一致失效
        mvc.perform(post("/auth/logout").cookie(s.cookie())
                        .header("X-CSRF-TOKEN", s.csrfToken()))
                .andExpect(status().isOk());
        MvcResult after = mvc.perform(get("/api/user/profile").cookie(s.cookie()))
                .andExpect(status().isUnauthorized())
                .andReturn();
        log.info("after logout: body={}", after.getResponse().getContentAsString());
        assertTrue(after.getResponse().getContentAsString().contains("SESSION_MISSING"));
    }

    @Test
    void loginFailureIsUniformForUnknownUserAndBadPassword() throws Exception {
        MvcResult bad = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized()).andReturn();
        MvcResult unknown = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"ghost\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("badPassword body={}, unknownUser body={}",
                bad.getResponse().getContentAsString(), unknown.getResponse().getContentAsString());
        assertEquals(bad.getResponse().getContentAsString(),
                unknown.getResponse().getContentAsString(),
                "账号不存在与口令错误响应必须完全一致");
        assertNull(bad.getResponse().getHeader(HttpHeaders.SET_COOKIE), "失败不得签发 Cookie");
    }

    @Test
    void forbiddenLooksLikeNotFound() throws Exception {
        Session alice = login("alice", "alice-pass");
        MvcResult forbidden = mvc.perform(get("/api/admin/dashboard").cookie(alice.cookie()))
                .andExpect(status().isNotFound()).andReturn();
        MvcResult nonexistent = mvc.perform(get("/api/admin/nope").cookie(alice.cookie()))
                .andExpect(status().isNotFound()).andReturn();
        log.info("forbidden body={}, nonexistent body={}",
                forbidden.getResponse().getContentAsString(), nonexistent.getResponse().getContentAsString());
        assertEquals(nonexistent.getResponse().getContentAsString(),
                forbidden.getResponse().getContentAsString(),
                "越权与资源不存在响应必须一致，不暴露资源存在性");
    }

    @Test
    void csrfRequiredForStateChangingRequests() throws Exception {
        Session s = login("alice", "alice-pass");
        // 缺少令牌
        MvcResult missing = mvc.perform(post("/api/user/transfer").cookie(s.cookie()))
                .andExpect(status().isForbidden()).andReturn();
        log.info("csrf missing: {}", missing.getResponse().getContentAsString());
        assertTrue(missing.getResponse().getContentAsString().contains("CSRF_TOKEN_MISSING"));
        // 错误令牌
        MvcResult wrong = mvc.perform(post("/api/user/transfer").cookie(s.cookie())
                        .header("X-CSRF-TOKEN", "forged"))
                .andExpect(status().isForbidden()).andReturn();
        assertTrue(wrong.getResponse().getContentAsString().contains("CSRF_TOKEN_MISMATCH"));
        // 正确令牌
        mvc.perform(post("/api/user/transfer").cookie(s.cookie())
                        .header("X-CSRF-TOKEN", s.csrfToken()))
                .andExpect(status().isOk());
    }

    @Test
    void concurrentDuplicateLoginsAndLogoutsAreConsistent() throws Exception {
        int n = 8;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);

        // 并发重复登录：全部成功且会话 ID 各不相同
        List<Future<Session>> logins = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            logins.add(pool.submit(() -> {
                start.await();
                return login("alice", "alice-pass");
            }));
        }
        start.countDown();
        List<String> ids = new ArrayList<>();
        for (Future<Session> f : logins) {
            ids.add(f.get(10, TimeUnit.SECONDS).cookie().getValue());
        }
        log.info("concurrent logins: n={}, distinctIds={}", n, ids.stream().distinct().count());
        assertEquals(n, ids.stream().distinct().count(), "并发登录不得串号");

        // 并发重复注销同一会话：全部返回稳定成功，之后访问一致 401
        Session victim = login("bob", "bob-pass");
        CountDownLatch start2 = new CountDownLatch(1);
        List<Future<Integer>> logouts = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            logouts.add(pool.submit(() -> {
                start2.await();
                return mvc.perform(post("/auth/logout").cookie(victim.cookie())
                                .header("X-CSRF-TOKEN", victim.csrfToken()))
                        .andReturn().getResponse().getStatus();
            }));
        }
        start2.countDown();
        for (Future<Integer> f : logouts) {
            assertEquals(200, f.get(10, TimeUnit.SECONDS), "重复注销必须幂等成功");
        }
        mvc.perform(get("/api/user/profile").cookie(victim.cookie()))
                .andExpect(status().isUnauthorized());
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
    }
}
