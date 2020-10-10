package com.github.tt4g.spring.webflux.security.custom.authentication.example.security;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.codec.HttpMessageReader;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.reactive.function.BodyExtractors;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class JsonLoginServerAuthenticationConverter implements ServerAuthenticationConverter {

    private final List<HttpMessageReader<?>> httpMessageReaders;

    public JsonLoginServerAuthenticationConverter(ServerCodecConfigurer serverCodecConfigurer) {
        this(serverCodecConfigurer.getReaders());
    }

    public JsonLoginServerAuthenticationConverter(List<HttpMessageReader<?>> httpMessageReaders) {
        this.httpMessageReaders = Objects.requireNonNull(httpMessageReaders);
    }


    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        // Can use ServerRequest#create(ServerWebExchange, List<HttpMessageReader<?>>)
        // for converting ServerWebExchange to ServerRequest.
        return ServerRequest.create(exchange, this.httpMessageReaders)
            .body(BodyExtractors.toMono(JsonParameter.class))
            .map(JsonAuthentication::new);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class JsonParameter {
        private final String username;

        private final String password;

        @JsonCreator
        public JsonParameter(
            @JsonProperty("username") String username,
            @JsonProperty("password") String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return this.username;
        }

        public String getPassword() {
            return this.password;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            JsonParameter that = (JsonParameter) o;
            return Objects.equals(username, that.username) &&
                Objects.equals(password, that.password);
        }

        @Override
        public int hashCode() {
            return Objects.hash(username, password);
        }

        @Override
        public String toString() {
            return "JsonParameter(" +
                "username=" + this.username +
                ", password=" + this.password +
                ")";
        }

    }

    static class JsonAuthentication implements Authentication, Serializable {

        private static final long serialVersionUID = 82338783974149196L;
        private final JsonParameter jsonParameter;

        public JsonAuthentication(JsonParameter jsonParameter) {
            this.jsonParameter = Objects.requireNonNull(jsonParameter);
        }

        public JsonParameter getJsonParameter() {
            return this.jsonParameter;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return List.of();
        }

        @Override
        public Object getCredentials() {
            return this.jsonParameter.getPassword();
        }

        @Override
        public Object getDetails() {
            return null;
        }

        @Override
        public Object getPrincipal() {
            return this.jsonParameter.getUsername();
        }

        @Override
        public boolean isAuthenticated() {
            return false;
        }

        @Override
        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

        }

        @Override
        public String getName() {
            return this.jsonParameter.getUsername();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            JsonAuthentication that = (JsonAuthentication) o;
            return Objects.equals(jsonParameter, that.jsonParameter);
        }

        @Override
        public int hashCode() {
            return Objects.hash(jsonParameter);
        }

        @Override
        public String toString() {
            return "JsonAuthentication(" +
                "jsonParameter=" + this.jsonParameter +
                ")";
        }
    }
}
