package com.github.tt4g.spring.webflux.security.custom.authentication.example.security;

import org.springframework.security.core.AuthenticationException;

/**
 * Report the fact that the authentication failed to Spring Security.
 */
public class FormLoginAuthenticationFailedException extends AuthenticationException {

    private static final long serialVersionUID = -8727951844439056257L;

    public FormLoginAuthenticationFailedException(String msg) {
        super(msg);
    }

}
