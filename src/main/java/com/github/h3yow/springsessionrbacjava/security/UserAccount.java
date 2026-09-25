package com.github.h3yow.springsessionrbacjava.security;

import java.util.Set;

/**
 * 用户账号：用户名、口令哈希与角色集合。
 */
public class UserAccount {

    private final String username;
    private final String passwordHash;
    private final Set<String> roles;

    public UserAccount(String username, String passwordHash, Set<String> roles) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.roles = roles;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public Set<String> getRoles() {
        return roles;
    }
}
