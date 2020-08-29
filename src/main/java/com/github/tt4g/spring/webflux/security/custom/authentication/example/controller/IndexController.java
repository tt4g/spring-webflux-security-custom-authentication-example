package com.github.tt4g.spring.webflux.security.custom.authentication.example.controller;

import com.github.tt4g.spring.webflux.security.custom.authentication.example.security.FormLoginUser;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.util.HtmlUtils;
import reactor.core.publisher.Mono;

@Controller
public class IndexController {

    @RequestMapping(path = "/", method = RequestMethod.GET)
    public Mono<ResponseEntity<String>> index(
        @AuthenticationPrincipal FormLoginUser formLoginUser) {

        String username = formLoginUser.getUsername();
        String domain = formLoginUser.getDomain();

        return Mono.just(
            ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body("<html>"
                    + "<head>"
                    + "<meta charset=\"utf-8\">"
                    + "<title>Login</title>"
                    + "</head>"
                    + "<body>"
                    + "<p>Hello, " + HtmlUtils.htmlEscape(username, "UTF-8") + "! </p>"
                    + "<p>Domain: " + HtmlUtils.htmlEscape(domain, "UTF-8") + "</p>"
                    + "</body>"
                    + "</html>"));
    }

}
