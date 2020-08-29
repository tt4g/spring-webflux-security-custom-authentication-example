package com.github.tt4g.spring.webflux.security.custom.authentication.example.security;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;

// 参考: org.springframework.security.authentication.UsernamePasswordAuthenticationToken
public class FormLoginAuthenticationToken
    implements Authentication, CredentialsContainer, Serializable {

    private static final long serialVersionUID = 3242634764188228695L;

    private final String username;

    private String password;

    private final String domain;

    private final boolean authenticated;

    FormLoginAuthenticationToken(String username, String password, String domain) {
        this.username = username;
        this.password = password;
        this.domain = domain;
        this.authenticated = false;
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public String getDomain() {
        return this.domain;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public Object getPrincipal() {
        return this.username;
    }

    @Override
    public Object getCredentials() {
        return this.password;
    }

    @Override
    public void eraseCredentials() {
        this.password = "";
    }

    @Override
    public Object getDetails() {
        return this.domain;
    }

    @Override
    public boolean isAuthenticated() {
        return this.authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        // N/A
    }

    @Override
    public String getName() {
        return this.username;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FormLoginAuthenticationToken that = (FormLoginAuthenticationToken) o;
        return authenticated == that.authenticated &&
            Objects.equals(username, that.username) &&
            Objects.equals(password, that.password) &&
            Objects.equals(domain, that.domain);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, password, domain, authenticated);
    }

    @Override
    public String toString() {
        return "FormLoginAuthenticationToken(" +
            "username=" + this.username +
            ", password=[PROTECTED]" +
            ", domain=" + this.domain +
            ", authenticated=" + this.authenticated +
            ")";
    }
}
