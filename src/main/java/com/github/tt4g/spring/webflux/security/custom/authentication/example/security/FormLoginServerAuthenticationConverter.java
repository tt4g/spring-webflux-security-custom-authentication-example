package com.github.tt4g.spring.webflux.security.custom.authentication.example.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;

import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class FormLoginServerAuthenticationConverter implements ServerAuthenticationConverter {

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        // HTML <form> から送られたパラメーターから認証情報の FormLoginAuthenticationToken を生成する。
        //
        // 参考: org.springframework.security.web.server.authentication.ServerFormLoginAuthenticationConverter
        //
        // NOTE: Mono<Authenticatoin> が生成できないときは Mono.empty() を返すと、
        // 認証情報が取得できなかったとみなされる。
        //
        // NOTE: JSONからパラメーターの取り出しをしたい場合などは、
        // org.springframework.http.codec.ServerCodecConfigurer を @Autowired して、
        // 以下のようなコードでJSONを読み取る。
        // この辺りはSpring SecurityのOAuth 2認証のAuthWebFilterの実装を参考にする。
        //
        // private static ResolvableType RESOLVE_TYPE = ResolvableType.forClass(YourJsonType.class);
        //
        // public Mono<Authentication> convert(ServerWebExchange exchange) {
        //     return serverCodecConfigurer.getReaders().stream()
        //         .filter(httpMessageReader -> httpMessageReader.canRead(ResolvableType, MediaType.APPLICATION_JSON))
        //         .findFirst()
        //         .orElseThrow(() -> new RuntimeException("YourJsonType can not read!"))
        //         .readMono(ResolvableType, request, Collections.emptyMap())
        //         .cast(YourJsonType.class)
        //         .map(yourJsonType -> new YourJsonAuthenticationToken(yourJsonType));
        return exchange.getFormData()
            .flatMap(this::createFormLoginAuthenticationToken);
    }

    private Mono<FormLoginAuthenticationToken> createFormLoginAuthenticationToken(
        MultiValueMap<String, String> formData) {

        // NOTE: ここで Mono.error() を返すと Internal Server Error になる。
        // パラメーターエラーは ReactiveAuthenticationManager.authenticate() で
        // 発生させなければいけない様子。

        String username = formData.getFirst("username");
        String password = formData.getFirst("password");
        String domain = formData.getFirst("domain");

        return Mono.just(new FormLoginAuthenticationToken(username, password, domain));
    }

}
