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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ttl=0 使会话签发即过期，验证过期原因在 HTTP 层可区分。
 */
@SpringBootTest(properties = "security.session-ttl-seconds=0")
@AutoConfigureMockMvc
class SessionExpiryWebTest {

    private static final Logger log = LoggerFactory.getLogger(SessionExpiryWebTest.class);

    @Autowired
    private MockMvc mvc;

    @Test
    void expiredSessionReportsDistinguishableReason() throws Exception {
        MvcResult login = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        String value = login.getResponse().getHeader(HttpHeaders.SET_COOKIE).split(";")[0].split("=")[1];
        String csrf = login.getResponse().getContentAsString()
                .replaceAll(".*\"csrfToken\":\"([^\"]+)\".*", "$1");

        MvcResult r = mvc.perform(get("/api/user/profile").cookie(new Cookie("SESSIONID", value)))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("expired session response: {}", r.getResponse().getContentAsString());
        assertTrue(r.getResponse().getContentAsString().contains("SESSION_EXPIRED"),
                "过期必须与缺失/注销可区分");

        MvcResult renew = mvc.perform(post("/auth/renew").cookie(new Cookie("SESSIONID", value))
                        .header("X-CSRF-TOKEN", csrf))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("renew expired response: {}", renew.getResponse().getContentAsString());
        assertTrue(renew.getResponse().getContentAsString().contains("SESSION_EXPIRED"),
                "过期会话不得通过续期复活");
    }
}
