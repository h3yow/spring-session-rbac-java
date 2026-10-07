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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ttl=0：自然过期在资源访问、续期、会话管理入口上结论一致（SESSION_EXPIRED），
 * 且与主动注销 SESSION_REVOKED、被挤 SESSION_CAP_EVICTED、缺失 SESSION_MISSING 可区分。
 */
@SpringBootTest(properties = "security.session-ttl-seconds=0")
@AutoConfigureMockMvc
class SessionExpiryManagementWebTest {

    private static final Logger log = LoggerFactory.getLogger(SessionExpiryManagementWebTest.class);

    @Autowired
    private MockMvc mvc;

    @Test
    void expiredReasonConsistentAcrossEntriesAndListHidesIt() throws Exception {
        MvcResult login = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        String sid = login.getResponse().getHeader(HttpHeaders.SET_COOKIE).split(";")[0].split("=")[1];
        Cookie cookie = new Cookie("SESSIONID", sid);

        MvcResult resource = mvc.perform(get("/api/user/profile").cookie(cookie))
                .andExpect(status().isUnauthorized()).andReturn();
        MvcResult renew = mvc.perform(post("/auth/renew").cookie(cookie).header("X-CSRF-TOKEN", "x"))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("expired: resource={}, renew={}",
                resource.getResponse().getContentAsString(), renew.getResponse().getContentAsString());
        assertTrue(resource.getResponse().getContentAsString().contains("SESSION_EXPIRED"));
        assertTrue(renew.getResponse().getContentAsString().contains("SESSION_EXPIRED"),
                "自然过期不得通过续期复活，且入口结论一致");
        // 会话管理入口同样以认证失败收口，不泄露任何会话信息
        mvc.perform(get("/api/sessions").cookie(cookie))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_EXPIRED"));

        // 与伪造 ID 的结果不同，但伪造 ID 仍然是稳定的 MISSING（不泄露）
        MvcResult forged = mvc.perform(get("/api/sessions").cookie(new Cookie("SESSIONID", "forged")))
                .andExpect(status().isUnauthorized()).andReturn();
        assertTrue(forged.getResponse().getContentAsString().contains("SESSION_MISSING"));
        log.info("expired vs missing distinguishable; forged stays MISSING");
    }
}
