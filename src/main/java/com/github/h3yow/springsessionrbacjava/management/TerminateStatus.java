package com.github.h3yow.springsessionrbacjava.management;

/**
 * 定向下线单个会话的结果。
 * NOT_FOUND 同时覆盖"不存在"与"属于其他账号"，调用方返回统一 404，不泄露会话归属。
 */
public enum TerminateStatus {
    REVOKED,
    NOT_FOUND
}
