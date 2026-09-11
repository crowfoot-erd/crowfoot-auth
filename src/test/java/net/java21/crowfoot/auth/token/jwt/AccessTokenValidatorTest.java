package net.java21.crowfoot.auth.token.jwt;

import net.java21.crowfoot.auth.config.TokenConfig;
import net.java21.crowfoot.auth.testsupport.MutableClock;
import net.java21.crowfoot.auth.testsupport.TestAuthProperties;
import net.java21.crowfoot.auth.testsupport.TestTokenFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class AccessTokenValidatorTest {

    private MutableClock clock;
    private AccessTokenValidator validator;

    @BeforeEach
    void setUp() {
        clock = MutableClock.atUtc2026();
        TokenConfig tokenConfig = new TokenConfig();
        JwtDecoder jwtDecoder = tokenConfig.jwtDecoder(TestTokenFactory.secretKey(), TestAuthProperties.create(), clock);
        JwtDecoder lenient = tokenConfig.lenientJwtDecoder(TestTokenFactory.secretKey());
        validator = new AccessTokenValidator(jwtDecoder, lenient, clock, TestAuthProperties.create());
    }

    @Test
    @DisplayName("유효한 Access 토큰 — active·sub·jti·sid 클레임 노출")
    void activeAccessToken() {
        IssuedToken token = new TestTokenFactory(clock).access("42", "sid-1");

        AccessTokenValidator.TokenCheck check = validator.check(token.value());

        assertThat(check.active()).isTrue();
        assertThat(check.jwt().getSubject()).isEqualTo("42");
        assertThat(check.jwt().getId()).isEqualTo(token.jti());
        assertThat(check.jwt().getClaimAsString("sid")).isEqualTo("sid-1");
    }

    @Test
    @DisplayName("만료(스큐 30s 초과) — inactiveReason EXPIRED")
    void expiredToken() {
        TestTokenFactory factory = new TestTokenFactory(clock);
        IssuedToken token = factory.access("42", "sid-1");

        clock.advanceBy(Duration.ofMinutes(60).plusSeconds(31));
        AccessTokenValidator.TokenCheck check = validator.check(token.value());

        assertThat(check.active()).isFalse();
        assertThat(check.inactiveReason()).isEqualTo(InactiveReason.EXPIRED);
    }

    @Test
    @DisplayName("다른 키로 서명(위조) — inactiveReason INVALID")
    void forgedToken() {
        byte[] other = new byte[32];
        new java.security.SecureRandom().nextBytes(other);
        String otherSecret = java.util.Base64.getEncoder().encodeToString(other);
        var properties = TestAuthProperties.create();
        var otherProps = new net.java21.crowfoot.auth.config.AuthProperties(
                properties.token(), properties.front(), properties.cookie(), properties.blacklist(),
                otherSecret, otherSecret);
        IssuedToken forged = new TestTokenFactory(clock, otherProps).access("42", "sid-1");

        AccessTokenValidator.TokenCheck check = validator.check(forged.value());

        assertThat(check.active()).isFalse();
        assertThat(check.inactiveReason()).isEqualTo(InactiveReason.INVALID);
    }

    @Test
    @DisplayName("Refresh 토큰은 Access 검증에서 거부 — inactiveReason INVALID")
    void refreshTokenRejected() {
        IssuedToken refresh = new TestTokenFactory(clock).refresh("42", "sid-1");

        AccessTokenValidator.TokenCheck check = validator.check(refresh.value());

        assertThat(check.active()).isFalse();
        assertThat(check.inactiveReason()).isEqualTo(InactiveReason.INVALID);
    }
}
