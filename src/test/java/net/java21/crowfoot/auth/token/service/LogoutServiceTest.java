package net.java21.crowfoot.auth.token.service;

import net.java21.crowfoot.auth.blacklist.BlacklistStore;
import net.java21.crowfoot.auth.client.CoreClient;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.config.TokenConfig;
import net.java21.crowfoot.auth.testsupport.MutableClock;
import net.java21.crowfoot.auth.testsupport.TestAuthProperties;
import net.java21.crowfoot.auth.testsupport.TestTokenFactory;
import net.java21.crowfoot.auth.token.RefreshCookieWriter;
import net.java21.crowfoot.auth.token.jwt.AccessTokenValidator;
import net.java21.crowfoot.auth.token.jwt.IssuedToken;
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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class LogoutServiceTest {

    private MutableClock clock;
    private TestTokenFactory factory;
    private LogoutService service;

    @Mock
    private CoreClient coreClient;

    @Mock
    private BlacklistStore blacklistStore;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        clock = MutableClock.atUtc2026();
        factory = new TestTokenFactory(clock);
        TokenConfig tokenConfig = new TokenConfig();
        JwtDecoder jwtDecoder = tokenConfig.jwtDecoder(TestTokenFactory.secretKey(), TestAuthProperties.create(), clock);
        JwtDecoder lenient = tokenConfig.lenientJwtDecoder(TestTokenFactory.secretKey());
        RefreshCookieWriter cookieWriter = new RefreshCookieWriter(TestAuthProperties.create());
        service = new LogoutService(
                new RefreshTokenParser(jwtDecoder, lenient, clock, TestAuthProperties.create()),
                new AccessTokenValidator(jwtDecoder, lenient, clock, TestAuthProperties.create()),
                coreClient, blacklistStore, cookieWriter, clock);
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
    @DisplayName("로그아웃 성공 — Refresh core 폐기(jti)·감사·유효 Access 블랙리스트(사유 LOGOUT)·쿠키 삭제")
    void logoutRevokesAndBlacklists() {
        IssuedToken refresh = factory.refresh("42", "sid-1");
        writeRefreshCookie(refresh);
        IssuedToken access = factory.access("42", "sid-1");
        request.addHeader("Authorization", "Bearer " + access.value());

        service.logout(request, response);

        verify(coreClient).revokeRefreshToken(refresh.jti());
        verify(coreClient).recordAuditLog(42L, "USER_LOGGED_OUT", "reason=logout");
        ArgumentCaptor<Duration> ttl = ArgumentCaptor.forClass(Duration.class);
        verify(blacklistStore).registerAccessToken(anyString(), org.mockito.ArgumentMatchers.eq("LOGOUT"), ttl.capture());
        assertThat(ttl.getValue()).isEqualTo(Duration.ofMinutes(60)); // TTL=잔여 수명
        assertThat(response.getHeader("Set-Cookie")).contains("Max-Age=0");
    }

    @Test
    @DisplayName("만료 직후 Refresh도 폐기 — parseLeniently로 jti 추출해 core DELETE")
    void expiredRefreshStillRevoked() {
        IssuedToken refresh = factory.refresh("42", "sid-1");
        writeRefreshCookie(refresh);
        clock.advanceBy(Duration.ofHours(6).plusSeconds(1));

        service.logout(request, response);

        verify(coreClient).revokeRefreshToken(refresh.jti());
    }

    @Test
    @DisplayName("무효 서명 Refresh — 폐기·감사 없이 조용히 스킵(멱등 진행), 쿠키는 삭제")
    void invalidRefreshSkipped() {
        request.setCookies(new jakarta.servlet.http.Cookie("crowfoot_refresh", "forged.token.sig"));

        service.logout(request, response);

        verify(coreClient, never()).revokeRefreshToken(anyString());
        verify(coreClient, never()).recordAuditLog(anyLong(), anyString(), anyString());
        assertThat(response.getHeader("Set-Cookie")).contains("Max-Age=0");
    }

    @Test
    @DisplayName("쿠키·Bearer 모두 없음 — 멱등 완료(아무 폐기 없이 쿠키 삭제만)")
    void logoutWithoutCredentialsIsIdempotent() {
        service.logout(request, response);

        verify(coreClient, never()).revokeRefreshToken(anyString());
        verify(blacklistStore, never()).registerAccessToken(anyString(), anyString(), any());
        assertThat(response.getHeader("Set-Cookie")).contains("Max-Age=0");
    }

    @Test
    @DisplayName("만료·무효 Access는 블랙리스트 등록 스킵")
    void expiredAccessNotBlacklisted() {
        IssuedToken access = factory.access("42", "sid-1");
        request.addHeader("Authorization", "Bearer " + access.value());
        clock.advanceBy(Duration.ofMinutes(60).plusSeconds(31));

        service.logout(request, response);

        verify(blacklistStore, never()).registerAccessToken(anyString(), anyString(), any());
    }

    @Test
    @DisplayName("Refresh 폐기 중 core 장애 — SERVICE_UNAVAILABLE 전파(로그아웃 성공으로 위장하지 않는다)")
    void coreFailurePropagates() {
        IssuedToken refresh = factory.refresh("42", "sid-1");
        writeRefreshCookie(refresh);
        org.mockito.Mockito.doThrow(new BusinessException(ErrorCode.SERVICE_UNAVAILABLE))
                .when(coreClient).revokeRefreshToken(anyString());

        assertThatThrownBy(() -> service.logout(request, response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.SERVICE_UNAVAILABLE);
    }
}
