package com.github.h3yow.springsessionrbacjava.auth;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存账号目录：账号查询、口令校验（加盐 SHA-256 + 常量时间比较）与角色查询。
 * 角色保存在服务端并支持运行时变更，已有会话的授权判定即时使用新角色。
 */
@Component
public class UserDirectory {

    private final Map<String, UserAccount> accounts = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public UserDirectory() {
        // 演示账号：口令仅用于本地验证，哈希存储。
        addUser("alice", "alice-pass", Set.of("USER"));
        addUser("bob", "bob-pass", Set.of("USER", "ADMIN"));
    }

    public void addUser(String username, String password, Set<String> roles) {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        String saltB64 = Base64.getEncoder().encodeToString(salt);
        accounts.put(username, new UserAccount(username, hash(password, saltB64), saltB64,
                Set.copyOf(roles)));
    }

    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(accounts.get(username));
    }

    /**
     * 校验口令。账号不存在时也执行一次等长哈希计算与比较，
     * 使响应时间与结果对外不可区分（不泄露账号是否存在）。
     */
    public boolean verifyPassword(String username, String password) {
        UserAccount account = accounts.get(username);
        String salt = account != null ? account.salt() : "AAAAAAAAAAAAAAAAAAAAAA==";
        String candidate = hash(password == null ? "" : password, salt);
        String expected = account != null ? account.passwordHash() : hash("", salt);
        return MessageDigest.isEqual(candidate.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8)) && account != null;
    }

    /** 实时角色查询：授权判定每次调用，角色变更即时生效。 */
    public Set<String> rolesOf(String username) {
        UserAccount account = accounts.get(username);
        return account != null ? account.roles() : Set.of();
    }

    public void setRoles(String username, Set<String> roles) {
        accounts.computeIfPresent(username, (u, a) ->
                new UserAccount(a.username(), a.passwordHash(), a.salt(), Set.copyOf(roles)));
    }

    private static String hash(String password, String saltB64) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(Base64.getDecoder().decode(saltB64));
            byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
