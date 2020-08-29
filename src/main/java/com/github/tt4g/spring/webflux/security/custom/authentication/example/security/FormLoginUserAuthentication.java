package com.github.tt4g.spring.webflux.security.custom.authentication.example.security;

import java.io.Serializable;
import java.util.Collection;
import java.util.Objects;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

// FormLoginAuthenticationManager.authenticate() が返す、
// 認証されたユーザー情報を getPrincipal() で返す Authentication の実装。
public class FormLoginUserAuthentication implements Authentication, Serializable {

    private final FormLoginUser principal;

    FormLoginUserAuthentication(FormLoginUser principal) {
        this.principal = Objects.requireNonNull(principal);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.principal.getAuthorities();
    }

    @Override
    public Object getCredentials() {
        return this.principal.getPassword();
    }

    @Override
    public Object getDetails() {
        return this.principal.getDomain();
    }

    @Override
    public FormLoginUser getPrincipal() {
        return this.principal;
    }

    @Override
    public boolean isAuthenticated() {
        return this.principal.isEnabled();
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        // N/A
    }

    @Override
    public String getName() {
        return this.principal.getUsername();
    }
}
