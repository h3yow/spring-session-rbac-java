package com.github.h3yow.springsessionrbacjava.web;

import com.github.h3yow.springsessionrbacjava.auth.AuthService;
import com.github.h3yow.springsessionrbacjava.rbac.AuthorizationService;
import com.github.h3yow.springsessionrbacjava.session.SessionStore;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 注册 CSRF 过滤器（最高优先级）与会话/授权拦截器（/api/**）。
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final AuthService authService;
    private final AuthorizationService authorizationService;
    private final SessionStore sessionStore;

    public WebConfig(AuthService authService, AuthorizationService authorizationService,
                     SessionStore sessionStore) {
        this.authService = authService;
        this.authorizationService = authorizationService;
        this.sessionStore = sessionStore;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new SessionInterceptor(authService, authorizationService))
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/public/**");
    }

    @Bean
    public FilterRegistrationBean<CsrfFilter> csrfFilter() {
        FilterRegistrationBean<CsrfFilter> bean = new FilterRegistrationBean<>(new CsrfFilter(sessionStore));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        bean.addUrlPatterns("/*");
        return bean;
    }
}
