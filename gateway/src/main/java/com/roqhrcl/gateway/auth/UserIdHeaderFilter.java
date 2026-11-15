package com.roqhrcl.gateway.auth;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * 서비스들은 X-User-Id만 믿는다. 그래서 gateway가 두 가지를 반드시 한다.
 * 1) 밖에서 들어온 X-User-Id는 무조건 지운다(공개 경로 포함). 안 지우면 아무나 남의 id를 사칭한다.
 * 2) JWT 검증을 통과한 요청에만 토큰의 sub로 X-User-Id를 다시 붙인다.
 */
@Component
public class UserIdHeaderFilter implements GlobalFilter, Ordered {

    public static final String USER_ID_HEADER = "X-User-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest stripped = exchange.getRequest().mutate()
                .headers(h -> h.remove(USER_ID_HEADER))
                .build();

        return exchange.getPrincipal()
                .filter(JwtAuthenticationToken.class::isInstance)
                .map(p -> ((JwtAuthenticationToken) p).getToken().getSubject())
                .map(userId -> stripped.mutate().header(USER_ID_HEADER, userId).build())
                .defaultIfEmpty(stripped)
                .flatMap(req -> chain.filter(exchange.mutate().request(req).build()));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
