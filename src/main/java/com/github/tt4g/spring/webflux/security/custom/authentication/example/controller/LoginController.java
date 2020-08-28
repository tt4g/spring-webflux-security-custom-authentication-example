package com.github.tt4g.spring.webflux.security.custom.authentication.example.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

@Controller
public class LoginController {

    @RequestMapping(path = "/login", method = RequestMethod.GET)
    public Mono<ResponseEntity<String>> login(
        ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();

        String loginUri =
            UriComponentsBuilder.fromPath(request.getPath().contextPath().value())
                .path("/login")
                .build()
                .toUriString();

        // Spring Security 5.3 では CsrfToken を @Controller の引数に指定できない。
        // ServerWebExchange から Mono<CsrfToken> を取得する方法しかない様子。
        //
        // See: * https://github.com/spring-projects/spring-security/issues/6046
        //      * https://github.com/spring-projects/spring-security/issues/4762
        Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
        if (csrfToken == null) {
            csrfToken = Mono.just(null);
        }

        return csrfToken.map(csrf ->
                ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body("<html>"
                    + "<head>"
                    + "<meta charset=\"utf-8\">"
                    + "<title>Login</title>"
                    + "</head>"
                    + "<body>"
                    + "<h1>Login</h1>"
                    + "<form action=\"" + loginUri + "\" method=\"POST\">"
                    + "<label for=\"username\">Username:</label>"
                    + "<input id=\"username\" name=\"username\" type=\"text\" value=\"\">"
                    + "<label for=\"password\">Password:</label>"
                    + "<input id=\"password\" name=\"password\" type=\"text\" value=\"\">"
                    + "<label for=\"domain\">Domain:</label>"
                    + "<input id=\"domain\" name=\"domain\" type=\"text\" value=\"\">"
                    + (csrf != null ?
                        "<input name=\"" + csrf.getParameterName() + "\""
                            + " type=\"hidden\" "
                            + "value=\"" + HtmlUtils.htmlEscape(csrf.getToken(), "UTF-8")
                            + "\">"
                        : "")
                    + "<input name=\"submit\" type=\"submit\" value=\"Submit\">"
                    + "</form>"
                    + "</body>"
                    + "</html>"));
    }
}
