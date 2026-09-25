package com.github.h3yow.springsessionrbacjava.auth;

import java.util.Set;

/**
 * 服务端持有的账号记录。角色只以服务端数据为准，客户端提交的角色不参与授权。
 */
public record UserAccount(String username, String passwordHash, String salt, Set<String> roles) {
}
