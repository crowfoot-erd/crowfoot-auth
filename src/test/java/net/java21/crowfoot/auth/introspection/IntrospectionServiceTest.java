package net.java21.crowfoot.auth.introspection;

import net.java21.crowfoot.auth.blacklist.BlacklistStore;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.config.TokenConfig;
import net.java21.crowfoot.auth.testsupport.MutableClock;
import net.java21.crowfoot.auth.testsupport.TestAuthProperties;
import net.java21.crowfoot.auth.testsupport.TestTokenFactory;
import net.java21.crowfoot.auth.token.jwt.AccessTokenValidator;
import net.java21.crowfoot.auth.token.jwt.IssuedToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IntrospectionServiceTest {

    private MutableClock clock;
    private TestTokenFactory factory;
    private IntrospectionService service;

    @Mock
    private BlacklistStore blacklistStore;

    @BeforeEach
    void setUp() {
        clock = MutableClock.atUtc2026();
        factory = new TestTokenFactory(clock);
        TokenConfig tokenConfig = new TokenConfig();
        JwtDecoder jwtDecoder = tokenConfig.jwtDecoder(TestTokenFactory.secretKey(), TestAuthProperties.create(), clock);
        JwtDecoder lenient = tokenConfig.lenientJwtDecoder(TestTokenFactory.secretKey());
        service = new IntrospectionService(
                new AccessTokenValidator(jwtDecoder, lenient, clock, TestAuthProperties.create()), blacklistStore);
    }

    @Test
    @DisplayName("활성 토큰 — active=true·sub·jti·sid·typ·iss·aud·iat·exp·inactiveReason=null")
    void activeTokenResponse() {
        IssuedToken token = factory.access("42", "sid-1");
        when(blacklistStore.findBlocked(token.jti(), "sid-1"))
                .thenReturn(new BlacklistStore.BlockResult(false, false));

        IntrospectionResponse response = service.introspect(token.value());

        assertThat(response.active()).isTrue();
        assertThat(response.sub()).isEqualTo("42");
        assertThat(response.jti()).isEqualTo(token.jti());
        assertThat(response.sid()).isEqualTo("sid-1");
        assertThat(response.typ()).isEqualTo("ACCESS");
        assertThat(response.iss()).isEqualTo("https://crowfoot-api.java21.net");
        assertThat(response.aud()).isEqualTo("crowfoot-web crowfoot-sync");
        assertThat(response.exp()).isEqualTo(clock.instant().plus(Duration.ofMinutes(60)).getEpochSecond());
        assertThat(response.inactiveReason()).isNull();
    }

    @Test
    @DisplayName("jti 블랙리스트(로그아웃) — active=false·inactiveReason REVOKED")
    void revokedTokenByJti() {
        IssuedToken token = factory.access("42", "sid-1");
        when(blacklistStore.findBlocked(token.jti(), "sid-1"))
                .thenReturn(new BlacklistStore.BlockResult(true, false));

        IntrospectionResponse response = service.introspect(token.value());

        assertThat(response.active()).isFalse();
        assertThat(response.inactiveReason()).isEqualTo("REVOKED");
    }

    @Test
    @DisplayName("sid 블랙리스트(세션 폐기) — active=false·inactiveReason REVOKED")
    void revokedTokenBySession() {
        IssuedToken token = factory.access("42", "sid-1");
        when(blacklistStore.findBlocked(token.jti(), "sid-1"))
                .thenReturn(new BlacklistStore.BlockResult(false, true));

        IntrospectionResponse response = service.introspect(token.value());

        assertThat(response.active()).isFalse();
        assertThat(response.inactiveReason()).isEqualTo("REVOKED");
    }

    @Test
    @DisplayName("만료 — active=false·inactiveReason EXPIRED(블랙리스트 조회 없음)")
    void expiredToken() {
        IssuedToken token = factory.access("42", "sid-1");
        clock.advanceBy(Duration.ofMinutes(60).plusSeconds(31));

        IntrospectionResponse response = service.introspect(token.value());

        assertThat(response.active()).isFalse();
        assertThat(response.inactiveReason()).isEqualTo("EXPIRED");
    }

    @Test
    @DisplayName("Refresh 토큰 introspection — active=false·INVALID(블랙리스트 조회 없음)")
    void refreshTokenIsInvalid() {
        IssuedToken refresh = factory.refresh("42", "sid-1");

        IntrospectionResponse response = service.introspect(refresh.value());

        assertThat(response.active()).isFalse();
        assertThat(response.inactiveReason()).isEqualTo("INVALID");
    }

    @Test
    @DisplayName("저장소 접근 불가 — SERVICE_UNAVAILABLE 전파(fail-closed)")
    void storeFailurePropagatesAs503() {
        IssuedToken token = factory.access("42", "sid-1");
        when(blacklistStore.findBlocked(any(), any()))
                .thenThrow(new BusinessException(ErrorCode.SERVICE_UNAVAILABLE));

        assertThatThrownBy(() -> service.introspect(token.value()))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.SERVICE_UNAVAILABLE);
    }
}
