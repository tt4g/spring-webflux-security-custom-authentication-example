package com.github.tt4g.spring.webflux.security.custom.authentication.example.security;

import java.util.Collections;
import java.util.Set;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

public class FormLoginAuthenticationManager implements ReactiveAuthenticationManager {

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.just(authentication)
            .cast(FormLoginAuthenticationToken.class)
            .flatMap(this::validate)
            // 不明なユーザーの場合は Mono.empty() になり認証に失敗する。
            .filter(this::isKnownUser)
            .map(this::authenticated);
    }

    Mono<FormLoginAuthenticationToken> validate(
        FormLoginAuthenticationToken formLoginAuthenticationToken) {
        // パラメーターエラーなどがある場合は、 ReactiveAuthenticationManager.authenticate() から
        // Mono.error() を返す。

        String username = formLoginAuthenticationToken.getUsername();
        if (!StringUtils.hasLength(username)) {
            return Mono.error(new InvalidFormLoginParameterException("username is empty."));
        }

        String password = formLoginAuthenticationToken.getPassword();
        if (!StringUtils.hasLength(password)) {
            return Mono.error(new InvalidFormLoginParameterException("password is empty."));
        }

        String domain = formLoginAuthenticationToken.getDomain();
        if (!StringUtils.hasLength(domain)) {
            return Mono.error(new InvalidFormLoginParameterException("domain is empty."));
        }

        return Mono.just(formLoginAuthenticationToken);
    }

    boolean isKnownUser(FormLoginAuthenticationToken formLoginAuthenticationToken) {
        return "user".equals(formLoginAuthenticationToken.getUsername())
            && "password".equals(formLoginAuthenticationToken.getPassword());
    }

    FormLoginUserAuthentication authenticated(FormLoginAuthenticationToken formLoginAuthenticationToken) {
        String username = formLoginAuthenticationToken.getUsername();
        String password = formLoginAuthenticationToken.getPassword();
        String domain = formLoginAuthenticationToken.getDomain();
        Set<GrantedAuthority> authorities = Collections.emptySet();

        FormLoginUser formLoginUser = new FormLoginUser(username, password, domain, authorities);

        return new FormLoginUserAuthentication(formLoginUser);
    }
}
