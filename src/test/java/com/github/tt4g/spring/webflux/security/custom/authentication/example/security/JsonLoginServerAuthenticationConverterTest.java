package com.github.tt4g.spring.webflux.security.custom.authentication.example.security;

import com.github.tt4g.spring.webflux.security.custom.authentication.example.security.JsonLoginServerAuthenticationConverter.JsonAuthentication;
import com.github.tt4g.spring.webflux.security.custom.authentication.example.security.JsonLoginServerAuthenticationConverter.JsonParameter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;

@WebFluxTest
public class JsonLoginServerAuthenticationConverterTest {

    @Autowired
    private ServerCodecConfigurer serverCodecConfigurer;

    private JsonLoginServerAuthenticationConverter jsonLoginServerAuthenticationConverter;

    @BeforeEach
    public void setUp() {
        this.jsonLoginServerAuthenticationConverter =
            new JsonLoginServerAuthenticationConverter(this.serverCodecConfigurer);
    }

    @Test
    public void convert() {
        MockServerHttpRequest mockServerHttpRequest =
            MockServerHttpRequest.post("/")
                .contentType(MediaType.APPLICATION_JSON)
            .body("{\"username\":\"foo\",\"password\":\"bar\"}");
        MockServerWebExchange mockServerWebExchange = MockServerWebExchange.from(mockServerHttpRequest);

        Authentication authentication =
            this.jsonLoginServerAuthenticationConverter.convert(mockServerWebExchange)
            .block();

        assertThat(authentication).isInstanceOf(JsonAuthentication.class);
        JsonParameter jsonParameter = ((JsonAuthentication) authentication).getJsonParameter();

        assertThat(jsonParameter).isEqualTo(new JsonParameter("foo", "bar"));
    }

}
