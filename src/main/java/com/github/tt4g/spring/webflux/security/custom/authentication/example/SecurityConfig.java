package com.github.tt4g.spring.webflux.security.custom.authentication.example;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange(authorizeExchangeSpec -> {
                authorizeExchangeSpec.pathMatchers(HttpMethod.OPTIONS).permitAll();
                authorizeExchangeSpec.pathMatchers("/public").permitAll();
                authorizeExchangeSpec.pathMatchers("/login").permitAll();
                authorizeExchangeSpec.anyExchange().authenticated();
            })
            .anonymous().disable()
            .csrf(csrfSpec -> {
                csrfSpec.csrfTokenRepository(
                    CookieServerCsrfTokenRepository.withHttpOnlyFalse());
            })
            // WebSessionServerSecurityContextRepository を通じて、
            // WEBのセッションにSpring Securityオブジェクトを保存する。
            .securityContextRepository(new WebSessionServerSecurityContextRepository())
            .httpBasic().disable()
            .formLogin(formLoginSpec -> {
                formLoginSpec
                    // /login へアクセスさせることでログイン用のページを表示する。
                    // NOTE: formLoginSpec.loginPage() を呼び出すと、
                    //       内部で formLoginSpec.authenticationEntryPoint() と
                    //       formLoginSpec.authenticationFailureHandler() に
                    //       ここで指定したパスを設定している。
                    //       authenticationEntryPoint() には
                    //       RedirectServerAuthenticationEntryPoint を渡して認証されていないと。
                    //       /login リダイレクトするように設定される。
                    //       authenticationFailureHandler() には
                    //       RedirectServerAuthenticationFailureHandler に /login?error を
                    //       渡してリダイレクトするように設定している。
                    .loginPage("/login")
                    // /login に POST メソッドでリクエストが行われたら認証を行う。
                    .requiresAuthenticationMatcher(
                        ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/login"))
                    // 認証を実施する AuthenticationManager の実態。
                    .authenticationManager(null)
                    .authenticationSuccessHandler(null)
                    .authenticationFailureHandler(null);
            })
            .logout(logoutSpec -> {
                logoutSpec
                    // /logout に POST メソッドでリクエストされたらログアウトする。
                    // 内部では logoutSpec.requiresLogout() に
                    // ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, logoutUrl) を渡している。
                    .logoutUrl("/logout")
                    .logoutSuccessHandler(null);
            })
            .exceptionHandling(exceptionHandlingSpec -> {
                exceptionHandlingSpec.accessDeniedHandler(null);
            })
            .headers(header -> {
                // Spring Security 特有のキャッシュ制御ヘッダーを無効化。
                // Cache-Control: no-cache, no-store, max-age=0, must-revalidate
                // Pragma: no-cache"
                // Expires: 0
                header.cache().disable();
                // X-Content-Type-Options: nosniff ヘッダーを出力する。
                header.contentTypeOptions();
                // Strict-Transport-Security ヘッダーを出力しない。
                header.hsts().disable();
                // X-Frame-Options: DENY ヘッダーを出力する。
                header.frameOptions(frameOptionsSpec -> {
                    frameOptionsSpec.mode(XFrameOptionsServerHttpHeadersWriter.Mode.DENY);
                });
                // X-XSS-Protection: 1; mode=block ヘッダーを出力する。
                header.xssProtection();
                // Content-Security-Policy: default-src 'self' ヘッダーを出力する。
                header.contentSecurityPolicy(contentSecurityPolicySpec -> {
                    contentSecurityPolicySpec.policyDirectives("default-src 'self'");
                });
                // Referrer-Policy: same-origin ヘッダーを出力する。
                header.referrerPolicy(referrerPolicySpec -> {
                    referrerPolicySpec.policy(ReferrerPolicy.SAME_ORIGIN);
                });
            })
            // CORS を無効化。
            .cors().disable()
            // 条件付きで http:// から https:// にリダイレクトさせる WebFilter を使用しない。
            //// .redirectToHttps()

            // 認証が必要なURLにアクセスして、認証URLにリダイレクトした場合、
            // 認証成功後に以前アクセスしていたURLにリダイレクトさせるリクエストキャッシュを有効化。
            .requestCache().and()

            .build();
    }

}
