package net.java21.crowfoot.auth.oauth2.service;

import net.java21.crowfoot.auth.client.CoreClient;
import net.java21.crowfoot.auth.client.dto.ProviderResponse;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.oauth2.AuthFlowCookieService;
import net.java21.crowfoot.auth.testsupport.TestAuthProperties;
import net.java21.crowfoot.auth.testsupport.TestClientRegistrations;
import net.java21.crowfoot.auth.testsupport.TestTokenFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import tools.jackson.databind.ObjectMapper;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginStartServiceTest {

    private LoginStartService service;

    @Mock
    private CoreClient coreClient;

    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;

    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        AuthFlowCookieService cookieService = new AuthFlowCookieService(
                TestTokenFactory.secretKey(), TestAuthProperties.create(), new ObjectMapper());
        service = new LoginStartService(coreClient, clientRegistrationRepository, cookieService);
        response = new MockHttpServletResponse();
    }

    @Test
    @DisplayName("로그인 시작 — authorize URL에 redirect_uri(프론트 콜백)·state·client_id·scope 포함 + auth_flow 쿠키 발행")
    void startReturnsAuthorizeUrlAndCookie() {
        ClientRegistration github = TestClientRegistrations.github();
        when(coreClient.activeProviders()).thenReturn(List.of(new ProviderResponse("github", "GitHub")));
        when(clientRegistrationRepository.findByRegistrationId("github")).thenReturn(github);

        String url = service.start("github", response);

        assertThat(url).startsWith("https://github.com/login/oauth/authorize");
        assertThat(url).contains("redirect_uri=http://localhost:8080/auth/callback");
        assertThat(url).contains("client_id=test-client-id");
        assertThat(url).contains("state=");
        assertThat(url).contains("scope=");
        assertThat(response.getHeader("Set-Cookie")).startsWith("auth_flow=");
    }

    @Test
    @DisplayName("core 비활성(제공자 목록에 없음) — RESOURCE_NOT_FOUND")
    void inactiveProviderThrows404() {
        when(coreClient.activeProviders()).thenReturn(List.of(new ProviderResponse("google", "Google")));

        assertThatThrownBy(() -> service.start("github", response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.RESOURCE_NOT_FOUND);
    }

    @Test
    @DisplayName("core 장애 — SERVICE_UNAVAILABLE 전파(fail-closed)")
    void coreFailurePropagates503() {
        when(coreClient.activeProviders())
                .thenThrow(new BusinessException(ErrorCode.SERVICE_UNAVAILABLE));

        assertThatThrownBy(() -> service.start("github", response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.SERVICE_UNAVAILABLE);
    }

    @Test
    @DisplayName("활성이지만 yml 등록 없음 — RESOURCE_NOT_FOUND(설정 누락)")
    void missingRegistrationThrows404() {
        when(coreClient.activeProviders()).thenReturn(List.of(new ProviderResponse("github", "GitHub")));
        when(clientRegistrationRepository.findByRegistrationId("github")).thenReturn(null);

        assertThatThrownBy(() -> service.start("github", response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.RESOURCE_NOT_FOUND);
    }
}
