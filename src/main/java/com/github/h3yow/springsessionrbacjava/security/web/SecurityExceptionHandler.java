package com.github.h3yow.springsessionrbacjava.security.web;

import java.util.Map;

import com.github.h3yow.springsessionrbacjava.security.AuthException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 统一安全异常 -> 稳定错误响应。
 * 越权与资源不存在统一为 404 + RESOURCE_NOT_AVAILABLE，不暴露资源是否存在。
 */
@RestControllerAdvice
public class SecurityExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handle(AuthException ex) {
        HttpStatus status = switch (ex.getReason()) {
            case INVALID_CREDENTIALS -> HttpStatus.UNAUTHORIZED;
            case RESOURCE_NOT_AVAILABLE -> HttpStatus.NOT_FOUND;
            default -> HttpStatus.FORBIDDEN;
        };
        return ResponseEntity.status(status).body(Map.of("error", ex.getReason().name()));
    }
}
