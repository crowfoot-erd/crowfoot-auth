package net.java21.crowfoot.auth.token.jwt;

import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RefreshTokenParserTest {

    private MutableClock clock;
    private RefreshTokenParser parser;

    @BeforeEach
    void setUp() {
        clock = MutableClock.atUtc2026();
        TokenConfig tokenConfig = new TokenConfig();
        parser = new RefreshTokenParser(
                tokenConfig.jwtDecoder(TestTokenFactory.secretKey(), TestAuthProperties.create(), clock),
                tokenConfig.lenientJwtDecoder(TestTokenFactory.secretKey()),
                clock, TestAuthProperties.create());
    }

    @Test
    @DisplayName("Refresh 파싱 — sub·jti·sid·exp 추출")
    void parseRefreshClaims() {
        TestTokenFactory factory = new TestTokenFactory(clock);
        IssuedToken token = factory.refresh("42", "sid-1");

        RefreshTokenParser.RefreshClaims claims = parser.parse(token.value());

        assertThat(claims.sub()).isEqualTo("42");
        assertThat(claims.jti()).isEqualTo(token.jti());
        assertThat(claims.sid()).isEqualTo("sid-1");
        assertThat(claims.expiresAt()).isEqualTo(clock.instant().plus(Duration.ofHours(6)));
    }

    @Test
    @DisplayName("만료 Refresh — AUTH_TOKEN_EXPIRED")
    void expiredRefreshThrows() {
        TestTokenFactory factory = new TestTokenFactory(clock);
        IssuedToken token = factory.refresh("42", "sid-1");
        clock.advanceBy(Duration.ofHours(6).plusSeconds(31));

        assertThatThrownBy(() -> parser.parse(token.value()))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_TOKEN_EXPIRED);
    }

    @Test
    @DisplayName("위조·깨진 토큰 — AUTH_TOKEN_INVALID")
    void invalidTokenThrows() {
        assertThatThrownBy(() -> parser.parse("not-a-jwt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_TOKEN_INVALID);
    }

    @Test
    @DisplayName("Access 토큰을 Refresh 자리에 넣으면 — AUTH_TOKEN_INVALID")
    void accessTokenRejected() {
        IssuedToken access = new TestTokenFactory(clock).access("42", "sid-1");

        assertThatThrownBy(() -> parser.parse(access.value()))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_TOKEN_INVALID);
    }

    @Test
    @DisplayName("parseLeniently — 만료 직후 Refresh도 jti 추출 허용(로그아웃 폐기)")
    void parseLenientlyAllowsExpired() {
        TestTokenFactory factory = new TestTokenFactory(clock);
        IssuedToken token = factory.refresh("42", "sid-1");
        clock.advanceBy(Duration.ofHours(6).plusSeconds(1));

        RefreshTokenParser.RefreshClaims claims = parser.parseLeniently(token.value());

        assertThat(claims.jti()).isEqualTo(token.jti());
        assertThat(claims.sub()).isEqualTo("42");
    }

    @Test
    @DisplayName("parseLeniently — 서명 무효는 여전히 AUTH_TOKEN_INVALID")
    void parseLenientlyRejectsForged() {
        assertThatThrownBy(() -> parser.parseLeniently("forged.value.sig"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_TOKEN_INVALID);
    }
}
