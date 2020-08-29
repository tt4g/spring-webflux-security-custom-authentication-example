package com.github.tt4g.spring.webflux.security.custom.authentication.example.security;

import org.springframework.security.core.AuthenticationException;

public class InvalidFormLoginParameterException extends AuthenticationException {

    InvalidFormLoginParameterException(String msg) {
        super(msg);
    }

}
