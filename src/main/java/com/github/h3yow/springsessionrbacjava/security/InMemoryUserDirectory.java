package com.github.h3yow.springsessionrbacjava.security;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 内存用户目录（本地验证用）。口令以 BCrypt 哈希存储。
 */
@Component
public class InMemoryUserDirectory implements UserDirectory {

    private final Map<String, UserAccount> users = new ConcurrentHashMap<>();

    public InMemoryUserDirectory() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        register("alice", encoder.encode("alice-pass"), Set.of("USER"));
        register("bob", encoder.encode("bob-pass"), Set.of("USER", "ADMIN"));
    }

    public void register(String username, String passwordHash, Set<String> roles) {
        users.put(username, new UserAccount(username, passwordHash, Set.copyOf(roles)));
    }

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }
}
