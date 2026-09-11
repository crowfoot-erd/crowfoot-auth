package net.java21.crowfoot.auth.testsupport;

import net.java21.crowfoot.auth.config.AuthProperties;

import java.time.Duration;
import java.util.List;

/**
 * 테스트 고정 AuthProperties — 시크릿은 Base64 32바이트 고정 더미(검증 통과 분).
 */
public final class TestAuthProperties {

    public static final String DUMMY_SECRET = java.util.Base64.getEncoder()
            .encodeToString(new byte[32]);

    private TestAuthProperties() {
    }

    public static AuthProperties create() {
        return new AuthProperties(new AuthProperties.Token(
                Duration.ofMinutes(60), Duration.ofHours(6), Duration.ofSeconds(30), Duration.ofSeconds(30),
                "https://crowfoot-api.java21.net", List.of("crowfoot-web", "crowfoot-sync")),
                new AuthProperties.Front("http://localhost:8080", "/auth/callback"),
                new AuthProperties.Cookie(false),
                new AuthProperties.Blacklist("memory"),
                DUMMY_SECRET, DUMMY_SECRET);
    }
}
