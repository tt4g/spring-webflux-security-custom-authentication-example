package com.github.tt4g.spring.webflux.security.custom.authentication.example.security;

import org.springframework.security.core.AuthenticationException;

public class InvalidFormLoginParameterException extends AuthenticationException {

    private static final long serialVersionUID = -6442967377916941223L;

    InvalidFormLoginParameterException(String msg) {
        super(msg);
    }

}
