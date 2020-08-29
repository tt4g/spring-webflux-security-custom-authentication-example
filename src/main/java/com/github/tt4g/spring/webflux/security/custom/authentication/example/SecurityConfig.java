package com.github.tt4g.spring.webflux.security.custom.authentication.example;

import java.net.URI;
import java.text.Normalizer.Form;

import com.github.tt4g.spring.webflux.security.custom.authentication.example.security.FormLoginAuthenticationManager;
import com.github.tt4g.spring.webflux.security.custom.authentication.example.security.FormLoginAuthenticationWebFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

@EnableWebFluxSecurity
public class SecurityConfig {

    private static final String LOGIN_PATH = "/login";

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
        ServerHttpSecurity http,
        FormLoginAuthenticationManager formLoginAuthenticationManager) {

        WebSessionServerSecurityContextRepository webSessionServerSecurityContextRepository =
            new WebSessionServerSecurityContextRepository();

        FormLoginAuthenticationWebFilter formLoginAuthenticationWebFilter =
            formLoginAuthenticationWebFilter(formLoginAuthenticationManager, webSessionServerSecurityContextRepository);

        return http
            .authorizeExchange(authorizeExchangeSpec -> {
                authorizeExchangeSpec.pathMatchers(HttpMethod.OPTIONS).permitAll();
                authorizeExchangeSpec.pathMatchers("/public").permitAll();
                authorizeExchangeSpec.pathMatchers(LOGIN_PATH).permitAll();
                authorizeExchangeSpec.anyExchange().authenticated();
            })
            .anonymous().disable()
            .csrf(csrfSpec -> {
                csrfSpec.csrfTokenRepository(
                    CookieServerCsrfTokenRepository.withHttpOnlyFalse());
            })
            // WebSessionServerSecurityContextRepository を通じて、
            // WEBのセッションにSpring Securityオブジェクトを保存する。
            .securityContextRepository(webSessionServerSecurityContextRepository)
            .httpBasic().disable()
            .formLogin().disable()
            // 独自認証を行う FormLoginAuthenticationWebFilter を
            // 認証処理を実施するフィルター (SecurityWebFiltersOrder.AUTHENTICATION) として登録。
            .addFilterAt(formLoginAuthenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .logout(logoutSpec -> {
                // /logout に POST メソッドでリクエストされたらログアウトする。
                // 内部では logoutSpec.requiresLogout() に
                // ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, logoutUrl) を渡している。
                logoutSpec.logoutUrl("/logout");

                // ログアウトしたら "/login" にリダイレクトさせる。
                RedirectServerLogoutSuccessHandler redirectServerLogoutSuccessHandler =
                    new RedirectServerLogoutSuccessHandler();
                redirectServerLogoutSuccessHandler.setLogoutSuccessUrl(URI.create(LOGIN_PATH));
                logoutSpec.logoutSuccessHandler(redirectServerLogoutSuccessHandler);
            })
            .exceptionHandling(exceptionHandlingSpec -> {
                // 認可エラーの時のレスポンスを返す。
                exceptionHandlingSpec.accessDeniedHandler(
                    new HttpStatusServerAccessDeniedHandler(HttpStatus.FORBIDDEN));

                // 認証していない状況で認可しようとしたり、 AuthenticationException が発生しなかった状況で
                // 呼び出しされる認証エントリポイント。
                // NOTE: ここで設定がされていない場合、 ExceptionTranslationWebFilter は
                // HTTP Basic認証を行うエントリポイントを使用する。
                // FormLoginSpec などを使用して AuthenticationWebFilter を生成している場合は
                // 自動的にその中で生成された ServerAuthenticationEntryPoint が使われるが、
                // 独自の AuthenticationWebFilter を用意している場合は、手動で設定を行う必要がある。
                exceptionHandlingSpec.authenticationEntryPoint(
                    new RedirectServerAuthenticationEntryPoint(LOGIN_PATH));
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

    @Bean
    protected FormLoginAuthenticationManager formLoginAuthenticationManager() {
        return new FormLoginAuthenticationManager();
    }

    FormLoginAuthenticationWebFilter formLoginAuthenticationWebFilter(
        FormLoginAuthenticationManager formLoginAuthenticationManager,
        ServerSecurityContextRepository serverSecurityContextRepository) {

        // 独自の認証処理を行おうとしたとき、HTTPリクエストなどから認証情報を取り出すための
        // org.springframework.security.web.server.authentication.ServerAuthenticationConverter を
        // カスタマイズして AuthenticationWebFilter にセットする操作が
        // Spring Security 5.3 では提供されていない。
        // Spring Security の WebFlux 向け認証処理は AuthenticationWebFiler に
        // 以下のクラス群を渡すことで実現できるので、独自の AuthenticationWebFilter を構成している。
        //
        // * ServerAuthenticationConverter
        //     ServerWebExchange から ReactiveAuthenticationManager に渡す認証情報の
        //     Mono<Authentication> を生成する。
        //
        // * ReactiveAuthenticationManager
        //     ServerAuthenticationConverter が生成した Authentication が
        //     持つ認証情報から実際の認証を行う。
        //
        // NOTE: FormLoginSpec などはログイン方法などをまとめて提供してくれる操作なので、
        // リクエストパラメーターを解析する ServerAuthenticationConverter がセットできないのは
        // 当然ともいえる。

        // 独自の AuthenticationWebFilter の FormLoginAuthenticationWebFilter を生成。
        // コンストラクタ内で独自の ServerAuthenticationConverter 実装の
        // FormLoginServerAuthenticationConverter を生成している。
        FormLoginAuthenticationWebFilter formLoginAuthenticationWebFilter =
            new FormLoginAuthenticationWebFilter(formLoginAuthenticationManager);

        // 認証結果を格納するリポジトリ。
        formLoginAuthenticationWebFilter.setSecurityContextRepository(
            serverSecurityContextRepository);

        // "/login" に POST メソッドでリクエストが行われたら認証を行う。
        formLoginAuthenticationWebFilter.setRequiresAuthenticationMatcher(
            ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, LOGIN_PATH));
        // 認証に成功したら "/" にリダイレクトさせる。
        formLoginAuthenticationWebFilter.setAuthenticationSuccessHandler(
            new RedirectServerAuthenticationSuccessHandler("/"));
        // 認証に失敗したら "/login?error" にリダイレクトさせる。
        formLoginAuthenticationWebFilter.setAuthenticationFailureHandler(
            new RedirectServerAuthenticationFailureHandler(LOGIN_PATH + "?error"));

        return formLoginAuthenticationWebFilter;
    }

}
