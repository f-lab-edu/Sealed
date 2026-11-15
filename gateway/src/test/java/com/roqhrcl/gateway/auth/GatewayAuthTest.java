package com.roqhrcl.gateway.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.sun.net.httpserver.HttpServer;

/**
 * 가짜 서버 두 개:
 * - jwksServer: gateway의 JWT 디코더가 공개키를 받아 가는 곳 (auth-service의 JWKS 역할)
 * - backendServer: gateway가 요청을 넘기는 뒤쪽 서비스. 실제로 받은 X-User-Id를 기록한다.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class GatewayAuthTest {

    static final RSAKey AUTH_KEY = generateKey();     // auth-service의 진짜 키 (JWKS로 공개됨)
    static final RSAKey ATTACKER_KEY = generateKey(); // 공격자가 만든 키 (JWKS에 없음)

    /** 뒤쪽 서비스가 마지막으로 받은 X-User-Id. 요청이 안 왔으면 "NOT_CALLED". */
    static final AtomicReference<String> receivedUserId = new AtomicReference<>();
    static final HttpServer jwksServer = startFakeServer(false);
    static final HttpServer backendServer = startFakeServer(true);

    @Autowired
    WebTestClient client;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        String backend = "http://localhost:" + backendServer.getAddress().getPort();
        registry.add("services.sealed-uri", () -> backend);
        registry.add("services.auth-uri", () -> backend);
        registry.add("auth.jwk-set-uri",
                () -> "http://localhost:" + jwksServer.getAddress().getPort() + "/.well-known/jwks.json");
    }

    @BeforeEach
    void reset() {
        receivedUserId.set("NOT_CALLED");
    }

    @AfterAll
    static void stop() {
        jwksServer.stop(0);
        backendServer.stop(0);
    }

    @Test
    void 토큰이_없으면_401_Problem_Details이고_뒤로_넘기지_않는다() {
        client.get().uri("/api/sealeds/ping")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody().jsonPath("$.code").isEqualTo("AUTH_UNAUTHORIZED");

        assertThat(receivedUserId.get()).isEqualTo("NOT_CALLED");
    }

    @Test
    void 올바른_토큰이면_sub를_X_User_Id로_붙여_넘긴다() {
        client.get().uri("/api/sealeds/ping")
                .headers(h -> h.setBearerAuth(token(AUTH_KEY, "sealed-auth", Instant.now().plusSeconds(600))))
                .exchange()
                .expectStatus().isOk();

        assertThat(receivedUserId.get()).isEqualTo("42");
    }

    @Test
    void 밖에서_보낸_X_User_Id는_토큰의_sub로_덮어쓴다() {
        client.get().uri("/api/sealeds/ping")
                .headers(h -> h.setBearerAuth(token(AUTH_KEY, "sealed-auth", Instant.now().plusSeconds(600))))
                .header("X-User-Id", "999")
                .exchange()
                .expectStatus().isOk();

        assertThat(receivedUserId.get()).isEqualTo("42");
    }

    @Test
    void 공개_경로는_토큰_없이_통과하고_밖에서_보낸_X_User_Id는_지운다() {
        client.get().uri("/.well-known/jwks.json")
                .header("X-User-Id", "999")
                .exchange()
                .expectStatus().isOk();

        assertThat(receivedUserId.get()).isNull();
    }

    @Test
    void 다른_키로_서명한_토큰은_401() {
        expectRejected(token(ATTACKER_KEY, "sealed-auth", Instant.now().plusSeconds(600)));
    }

    @Test
    void 만료된_토큰은_401() {
        // 기본 허용 오차가 60초라 그보다 더 과거로
        expectRejected(token(AUTH_KEY, "sealed-auth", Instant.now().minusSeconds(120)));
    }

    @Test
    void 발급자가_다르면_401() {
        expectRejected(token(AUTH_KEY, "someone-else", Instant.now().plusSeconds(600)));
    }

    @Test
    void 내용을_바꾼_토큰은_401() {
        String[] parts = token(AUTH_KEY, "sealed-auth", Instant.now().plusSeconds(600)).split("\\.");
        String forgedPayload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"iss\":\"sealed-auth\",\"sub\":\"1\",\"exp\":9999999999}".getBytes(StandardCharsets.UTF_8));
        expectRejected(parts[0] + "." + forgedPayload + "." + parts[2]);
    }

    private void expectRejected(String token) {
        client.get().uri("/api/sealeds/ping")
                .headers(h -> h.setBearerAuth(token))
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(receivedUserId.get()).isEqualTo("NOT_CALLED");
    }

    private static String token(RSAKey key, String issuer, Instant expiresAt) {
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject("42")
                .issuedAt(expiresAt.minusSeconds(900))
                .expiresAt(expiresAt)
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(key.getKeyID()).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    private static RSAKey generateKey() {
        try {
            return new RSAKeyGenerator(2048).keyIDFromThumbprint(true).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static HttpServer startFakeServer(boolean recordUserId) {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            server.createContext("/", exchange -> {
                if (recordUserId) {
                    List<String> values = exchange.getRequestHeaders().get("X-User-Id");
                    receivedUserId.set(values == null ? null : String.join(",", values));
                }

                boolean jwks = exchange.getRequestURI().getPath().equals("/.well-known/jwks.json");
                byte[] body = (jwks ? new JWKSet(AUTH_KEY.toPublicJWK()).toString() : "pong")
                        .getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
            server.start();
            return server;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
