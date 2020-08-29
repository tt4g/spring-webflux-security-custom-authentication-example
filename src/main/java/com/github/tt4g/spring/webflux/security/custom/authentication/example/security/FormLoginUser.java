package com.github.tt4g.spring.webflux.security.custom.authentication.example.security;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

// 参考: org.springframework.security.core.userdetails.User
public class FormLoginUser implements CredentialsContainer, UserDetails, Serializable {

    private static final long serialVersionUID = 7932164576212772825L;

    private final String username;

    private String password;

    private final String domain;

    private final Set<GrantedAuthority> authorities;

    FormLoginUser( String username, String password, String domain, Set<? extends GrantedAuthority> authorities) {
        this.username = Objects.requireNonNull(username);
        this.password = Objects.requireNonNull(password);
        this.domain = Objects.requireNonNull(domain);
        this.authorities = Collections.unmodifiableSet(Objects.requireNonNull(authorities));
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public void eraseCredentials() {
        this.password = "";
    }

    public String getDomain() {
        return this.domain;
    }

    @Override
    public Set<GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FormLoginUser that = (FormLoginUser) o;
        return Objects.equals(username, that.username) &&
            Objects.equals(password, that.password) &&
            Objects.equals(domain, that.domain) &&
            Objects.equals(authorities, that.authorities);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, password, domain, authorities);
    }

    @Override
    public String toString() {
        return "FormLoginUser(" +
            "username=" + this.username +
            ", password=[PROTECTED]" +
            ", domain=" + this.domain +
            ", authorities=" + this.authorities +
            ")";
    }

}
