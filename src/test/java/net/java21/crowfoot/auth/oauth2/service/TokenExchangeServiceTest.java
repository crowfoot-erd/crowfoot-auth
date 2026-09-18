package net.java21.crowfoot.auth.oauth2.service;

import net.java21.crowfoot.auth.client.CoreCallException;
import net.java21.crowfoot.auth.client.CoreClient;
import net.java21.crowfoot.auth.client.dto.GetOrCreateUserResponse;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.oauth2.AuthFlowCookieService;
import net.java21.crowfoot.auth.oauth2.AuthFlowState;
import net.java21.crowfoot.auth.oauth2.ProviderProfileExtractor;
import net.java21.crowfoot.auth.oauth2.dto.TokenExchangeRequest;
import net.java21.crowfoot.auth.testsupport.TestAuthProperties;
import net.java21.crowfoot.auth.testsupport.TestClientRegistrations;
import net.java21.crowfoot.auth.testsupport.TestTokenFactory;
import net.java21.crowfoot.auth.token.RefreshCookieWriter;
import net.java21.crowfoot.auth.token.dto.TokenResponse;
import net.java21.crowfoot.auth.token.service.TokenIssueService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.user.OAuth2User;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenExchangeServiceTest {

    private static final String STATE = "state-abc";
    private static final String CODE = "gh-code-xyz";

    private TokenExchangeService service;

    @Mock
    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseClient;

    @Mock
    private DefaultOAuth2UserService oauth2UserService;

    @Mock
    private CoreClient coreClient;

    @Mock
    private TokenIssueService tokenIssueService;

    private ClientRegistration github;
    private AuthFlowCookieService cookieService;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        github = TestClientRegistrations.github();
        ClientRegistrationRepository repository = org.mockito.Mockito.mock(ClientRegistrationRepository.class);
        org.mockito.Mockito.lenient().when(repository.findByRegistrationId("github")).thenReturn(github);
        cookieService = new AuthFlowCookieService(TestTokenFactory.secretKey(),
                TestAuthProperties.create(), new ObjectMapper());
        service = new TokenExchangeService(repository, tokenResponseClient, oauth2UserService,
                cookieService, new ProviderProfileExtractor(), coreClient, tokenIssueService,
                new RefreshCookieWriter(TestAuthProperties.create()), TestAuthProperties.create());
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        writeFlowCookie(STATE);
    }

    private void writeFlowCookie(String state) {
        MockHttpServletResponse cookieResponse = new MockHttpServletResponse();
        cookieService.write(cookieResponse, new AuthFlowState(state, null, "github",
                github.getRedirectUri(), Set.of("read:user", "user:email")));
        String setCookie = cookieResponse.getHeader("Set-Cookie");
        request.setCookies(new jakarta.servlet.http.Cookie("auth_flow",
                setCookie.substring("auth_flow=".length(), setCookie.indexOf(';'))));
    }

    private OAuth2AccessTokenResponse tokenResponse() {
        return OAuth2AccessTokenResponse.withToken("gh-access")
                .tokenType(org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(3600)
                .build();
    }

    @Test
    @DisplayName("교환 성공 — 프로필 추출 → core 확보 → 토큰 발급 → crowfoot_refresh 발행·auth_flow 삭제·TokenResponse")
    void exchangeSuccess() {
        when(tokenResponseClient.getTokenResponse(any(OAuth2AuthorizationCodeGrantRequest.class)))
                .thenReturn(tokenResponse());
        OAuth2User oauth2User = org.mockito.Mockito.mock(OAuth2User.class);
        when(oauth2User.getAttributes()).thenReturn(Map.of("id", 12345, "login", "octocat",
                "name", "Octo Cat", "email", "octo@example.com"));
        when(oauth2UserService.loadUser(any(OAuth2UserRequest.class))).thenReturn(oauth2User);
        when(coreClient.getOrCreateUser("github", "12345", "octocat", "octo@example.com", "Octo Cat"))
                .thenReturn(new GetOrCreateUserResponse("42", true, false));
        TokenIssueService.IssuedTokens issued = new TokenIssueService.IssuedTokens("sid-1",
                new net.java21.crowfoot.auth.token.jwt.IssuedToken("access-value", "jti-a", null),
                new net.java21.crowfoot.auth.token.jwt.IssuedToken("refresh-value", "jti-r", null));
        when(tokenIssueService.issueForLogin("42", "github", "127.0.0.1", null)).thenReturn(issued);

        TokenResponse result = service.exchange("github",
                new TokenExchangeRequest(CODE, STATE), request, response);

        assertThat(result.accessToken()).isEqualTo("access-value");
        assertThat(result.tokenType()).isEqualTo("Bearer");
        assertThat(result.expiresIn()).isEqualTo(3600L);
        // Refresh는 쿠키로, auth_flow는 삭제로 — Set-Cookie는 2건 발행된다
        assertThat(response.getHeaders("Set-Cookie").toString()).contains("crowfoot_refresh=refresh-value");
        assertThat(response.getHeaders("Set-Cookie").toString()).contains("auth_flow=;");
    }

    @Test
    @DisplayName("state 불일치 — AUTH_STATE_INVALID")
    void stateMismatchThrows() {
        assertThatThrownBy(() -> service.exchange("github",
                new TokenExchangeRequest(CODE, "different-state"), request, response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_STATE_INVALID);
    }

    @Test
    @DisplayName("auth_flow 쿠키 부재 — AUTH_STATE_INVALID")
    void missingCookieThrows() {
        request.setCookies();

        assertThatThrownBy(() -> service.exchange("github",
                new TokenExchangeRequest(CODE, STATE), request, response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_STATE_INVALID);
    }

    @Test
    @DisplayName("쿠키의 registrationId와 요청 provider 불일치 — AUTH_STATE_INVALID")
    void providerMismatchThrows() {
        assertThatThrownBy(() -> service.exchange("google",
                new TokenExchangeRequest(CODE, STATE), request, response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_STATE_INVALID);
    }

    @Test
    @DisplayName("제공자 토큰 교환 실패(잘못된 code) — AUTH_PROVIDER_ERROR(502)")
    void exchangeFailureThrows502() {
        when(tokenResponseClient.getTokenResponse(any(OAuth2AuthorizationCodeGrantRequest.class)))
                .thenThrow(new OAuth2AuthorizationException(new OAuth2Error("invalid_grant")));

        assertThatThrownBy(() -> service.exchange("github",
                new TokenExchangeRequest(CODE, STATE), request, response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_PROVIDER_ERROR);
    }

    @Test
    @DisplayName("UserInfo 프로필 실패 — AUTH_PROVIDER_ERROR(502)")
    void profileFailureThrows502() {
        when(tokenResponseClient.getTokenResponse(any(OAuth2AuthorizationCodeGrantRequest.class)))
                .thenReturn(tokenResponse());
        when(oauth2UserService.loadUser(any(OAuth2UserRequest.class)))
                .thenThrow(new OAuth2AuthenticationException(new OAuth2Error("userinfo_error")));

        assertThatThrownBy(() -> service.exchange("github",
                new TokenExchangeRequest(CODE, STATE), request, response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.AUTH_PROVIDER_ERROR);
    }

    @Test
    @DisplayName("탈퇴 계정(core 409 USER_WITHDRAWN) — USER_WITHDRAWN(409) 전파")
    void withdrawnUserPropagates409() {
        when(tokenResponseClient.getTokenResponse(any(OAuth2AuthorizationCodeGrantRequest.class)))
                .thenReturn(tokenResponse());
        OAuth2User oauth2User = org.mockito.Mockito.mock(OAuth2User.class);
        when(oauth2User.getAttributes()).thenReturn(Map.of("id", 12345, "login", "gone"));
        when(oauth2UserService.loadUser(any(OAuth2UserRequest.class))).thenReturn(oauth2User);
        when(coreClient.getOrCreateUser(eq("github"), eq("12345"), eq("gone"), isNull(), eq("gone")))
                .thenThrow(new CoreCallException("USER_WITHDRAWN", "탈퇴한 계정입니다"));

        assertThatThrownBy(() -> service.exchange("github",
                new TokenExchangeRequest(CODE, STATE), request, response))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.USER_WITHDRAWN);
    }
}
