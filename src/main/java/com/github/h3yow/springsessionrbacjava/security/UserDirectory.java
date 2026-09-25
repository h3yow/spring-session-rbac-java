package com.github.h3yow.springsessionrbacjava.security;

import java.util.Optional;

/**
 * 用户目录：按用户名查找账号。
 */
public interface UserDirectory {

    Optional<UserAccount> findByUsername(String username);
}
