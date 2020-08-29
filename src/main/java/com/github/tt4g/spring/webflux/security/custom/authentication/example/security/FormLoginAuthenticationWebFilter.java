package com.github.tt4g.spring.webflux.security.custom.authentication.example.security;

import org.springframework.security.web.server.authentication.AuthenticationWebFilter;

public class FormLoginAuthenticationWebFilter extends AuthenticationWebFilter {

    public FormLoginAuthenticationWebFilter(
        FormLoginAuthenticationManager formLoginAuthenticationManager) {
        super(formLoginAuthenticationManager);

        // このフィルターが認証を行うときに ServerWebExchange から Mono<Authentication> を生成する
        // FormLoginServerAuthenticationConverter をセットする。
        // FormLoginServerAuthenticationConverter が生成した FormLoginAuthenticationToken が
        // FormLoginAuthenticationManager.authenticate() に渡される。
        setServerAuthenticationConverter(new FormLoginServerAuthenticationConverter());
    }

}
