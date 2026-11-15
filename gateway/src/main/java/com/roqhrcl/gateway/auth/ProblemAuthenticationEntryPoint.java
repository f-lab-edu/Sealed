package com.roqhrcl.gateway.auth;

import java.nio.charset.StandardCharsets;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * 인증 실패(토큰 없음, 서명/만료/발급자 불일치)를 401 Problem Details로 응답한다.
 * 서비스들의 오류 형식(type/title/status/detail/code)과 맞춰 FE가 한 가지 형식만 다루게 한다.
 * 왜 실패했는지(만료인지 위조인지)는 응답에 쓰지 않는다. 공격자에게 힌트가 되기 때문.
 */
@Component
public class ProblemAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private static final String BODY = """
            {"type":"about:blank","title":"Unauthorized","status":401,\
            "detail":"인증이 필요합니다","code":"AUTH_UNAUTHORIZED"}""";

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        DataBuffer buffer = response.bufferFactory().wrap(BODY.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
}
