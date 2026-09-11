package net.java21.crowfoot.auth.token.service;

import net.java21.crowfoot.auth.client.CoreCallException;
import net.java21.crowfoot.auth.client.CoreClient;
import net.java21.crowfoot.auth.client.dto.RotateRefreshTokenResponse;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.config.TokenConfig;
import net.java21.crowfoot.auth.testsupport.MutableClock;
import net.java21.crowfoot.auth.testsupport.TestAuthProperties;
import net.java21.crowfoot.auth.testsupport.TestTokenFactory;
import net.java21.crowfoot.auth.token.RefreshCookieWriter;
import net.java21.crowfoot.auth.token.dto.TokenResponse;
import net.java21.crowfoot.auth.token.jwt.IssuedToken;
import net.java21.crowfoot.auth.token.jwt.JwtIssuer;
import net.java21.crowfoot.auth.token.jwt.RefreshTokenParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    private MutableClock clock;
    private RefreshTokenService service;
    private TestTokenFactory factory;

    @Mock
    private CoreClient coreClient;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        clock = MutableClock.atUtc2026();
        factory = new TestTokenFactory(clock);
        TokenConfig tokenConfig = new TokenConfig();
        JwtDecoder jwtDecoder = tokenConfig.jwtDecoder(TestTokenFactory.secretKey(), TestAuthProperties.create(), clock);
        JwtDecoder lenient = tokenConfig.lenientJwtDecoder(TestTokenFactory.secretKey());
        service = new RefreshTokenService(
                new RefreshTokenParser(jwtDecoder, lenient, clock, TestAuthProperties.create()),
                new JwtIssuer(TestTokenFactory.encoder(), clock, TestAuthProperties.create()),
                coreClient, new RefreshCookieWriter(TestAuthProperties.create()),
                TestAuthProperties.create());
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    private void writeRefreshCookie(IssuedToken token) {
        MockHttpServletResponse cookieResponse = new MockHttpServletResponse();
        new RefreshCookieWriter(TestAuthProperties.create()).write(cookieResponse, token);
        String setCookie = cookieResponse.getHeader("Set-Cookie");
        request.setCookies(new jakarta.servlet.http.Cookie("crowfoot_refresh",
                setCookie.substring("crowfoot_refresh=".length(), setCookie.indexOf(';'))));
    }

    @Test
    @DisplayName("ROTATED — 신규 jti Refresh 쿠키 재발행·Access 응답·rotate 인자(현재 jti→신규 jti·exp)·감사")
    void rotatedIssuesNewTokens() {
        IssuedToken current = factory.refresh("42", "sid-1");
        writeRefreshCookie(current);
        when(coreClient.rotateRefreshToken(eq(42L), eq(current.jti()), any(String.class), any(java.time.Instant.class)))
                .thenReturn(new RotateRefreshTokenResponse("ROTATED", null));

        TokenResponse result = service.refresh(request, response);

        assertThat(result.accessToken()).isNotBlank();
        assertThat(result.tokenType()).isEqualTo("Bearer");
        assertThat(result.expiresIn()).isEqualTo(3600L);
        // 새 Refresh가 쿠키로 나간다(값은 rotate에 심은 신규 jti 토큰)
        ArgumentCaptor<String> newJti = ArgumentCaptor.forClass(String.class);
        verify(coreClient).rotateRefreshToken(eq(42L), eq(current.jti()), newJti.capture(), any(java.time.Instant.class));
        String setCookie = response.getHeader("Set-Cookie");
        assertThat(setCookie).contains("crowfoot_refresh=");
        assertThat(setCookie).doesNotContain(current.value());
        verify(coreClient).recordAuditLog(eq(42L), eq("TOKEN_REFRESHED"), eq("verdict=ROTATED"));
    }

    @Test
    @DisplayName("GRACE — core가 알려준 lineage 최신 jti(latestJti)를 승계 발급(멀티탭 유예)")
    void graceIssuesWithLatestJti() {
        IssuedToken stale = factory.refreshWithJti("42", "sid-1", "old-jti");
        writeRefreshCookie(stale);
        when(coreClient.rotateRefreshToken(eq(42L), eq("old-jti"), any(String.class), any(java.time.Instant.class)))
                .thenReturn(new RotateRefreshTokenResponse("GRACE", "latest-jti"));

        service.refresh(request, response);

        // GRACE 토큰을 파싱해 jti가 latest-jti인지 확인 — 쿠키 값을 디코더로
        String setCookie = response.getHeader("Set-Cookie");
        String cookieValue = setCookie.substring("crowfoot_refresh=".length(), setCookie.indexOf(';'));
        var jwt = TestTokenFactory.decoder().decode(cookieValue);
        assertThat(jwt.getId()).isEqualTo("latest-jti");
        assertThat(jwt.getClaimAsString("sid")).isEqualTo("sid-1"); // sid 승계
        verify(coreClient).recordAuditLog(eq(42L), eq("TOKEN_REFRESHED"), eq("verdict=GRACE"));
    }

    @Test
    @DisplayName("GRACE인데 latestJti 없음 — AUTH_TOKEN_INVALID(계약 위반 방어)")
    void graceWithoutLatestJtiThrows() {
        IssuedToken stale = factory.refresh("42", "sid-1");
        writeRefreshCookie(stale);
        when(coreClient.rotateRefreshToken(anyLong(), any(String.class), any(String.class), any(java.time.Instant.class)))
                .thenReturn(new RotateRefreshTokenResponse("GRACE", null));

        assertThatThrownBy(() -> service.refresh(request, response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_TOKEN_INVALID);
    }

    @Test
    @DisplayName("쿠키 부재 — AUTH_TOKEN_INVALID(쿠키가 유일한 자격증명)")
    void missingCookieThrows() {
        assertThatThrownBy(() -> service.refresh(request, response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_TOKEN_INVALID);
    }

    @Test
    @DisplayName("만료 Refresh — AUTH_TOKEN_EXPIRED")
    void expiredRefreshThrows() {
        IssuedToken token = factory.refresh("42", "sid-1");
        writeRefreshCookie(token);
        clock.advanceBy(Duration.ofHours(6).plusSeconds(31));

        assertThatThrownBy(() -> service.refresh(request, response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_TOKEN_EXPIRED);
    }

    @Test
    @DisplayName("core 404(알 수 없는 jti) — AUTH_TOKEN_INVALID")
    void unknownJtiThrows() {
        IssuedToken token = factory.refresh("42", "sid-1");
        writeRefreshCookie(token);
        when(coreClient.rotateRefreshToken(anyLong(), any(String.class), any(String.class), any(java.time.Instant.class)))
                .thenThrow(new CoreCallException("REFRESH_TOKEN_NOT_FOUND", "대상 없음"));

        assertThatThrownBy(() -> service.refresh(request, response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_TOKEN_INVALID);
    }

    @Test
    @DisplayName("core 409(재사용 감지·세션 폐기) — AUTH_SESSION_REVOKED")
    void reuseDetectedThrows() {
        IssuedToken token = factory.refresh("42", "sid-1");
        writeRefreshCookie(token);
        when(coreClient.rotateRefreshToken(anyLong(), any(String.class), any(String.class), any(java.time.Instant.class)))
                .thenThrow(new CoreCallException("AUTH_SESSION_REVOKED", "재사용"));

        assertThatThrownBy(() -> service.refresh(request, response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_SESSION_REVOKED);
    }
}
