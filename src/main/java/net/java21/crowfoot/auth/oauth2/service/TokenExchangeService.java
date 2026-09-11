package net.java21.crowfoot.auth.oauth2.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.java21.crowfoot.auth.client.CoreCallException;
import net.java21.crowfoot.auth.client.CoreClient;
import net.java21.crowfoot.auth.client.dto.GetOrCreateUserResponse;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.config.AuthProperties;
import net.java21.crowfoot.auth.oauth2.AuthFlowCookieService;
import net.java21.crowfoot.auth.oauth2.AuthFlowState;
import net.java21.crowfoot.auth.oauth2.ProviderProfile;
import net.java21.crowfoot.auth.oauth2.ProviderProfileExtractor;
import net.java21.crowfoot.auth.oauth2.dto.TokenExchangeRequest;
import net.java21.crowfoot.auth.token.RefreshCookieWriter;
import net.java21.crowfoot.auth.token.dto.TokenResponse;
import net.java21.crowfoot.auth.token.service.TokenIssueService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;

/**
 * 인가 코드 교환 (02-auth/api.md Section 3.2) — 콜백 페이지가 넘긴 code·state로
 * 제공자 토큰 교환 → 프로필 → core 회원 확보 → 자체 토큰 발급을 수행한다.
 * 제공자 통신 실패는 502 AUTH_PROVIDER_ERROR, state 불일치는 400 AUTH_STATE_INVALID.
 */
@Service
public class TokenExchangeService {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseClient;
    private final DefaultOAuth2UserService oauth2UserService;
    private final AuthFlowCookieService authFlowCookieService;
    private final ProviderProfileExtractor profileExtractor;
    private final CoreClient coreClient;
    private final TokenIssueService tokenIssueService;
    private final RefreshCookieWriter refreshCookieWriter;
    private final AuthProperties properties;

    public TokenExchangeService(ClientRegistrationRepository clientRegistrationRepository,
                                OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseClient,
                                DefaultOAuth2UserService oauth2UserService,
                                AuthFlowCookieService authFlowCookieService,
                                ProviderProfileExtractor profileExtractor,
                                CoreClient coreClient,
                                TokenIssueService tokenIssueService,
                                RefreshCookieWriter refreshCookieWriter,
                                AuthProperties properties) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.tokenResponseClient = tokenResponseClient;
        this.oauth2UserService = oauth2UserService;
        this.authFlowCookieService = authFlowCookieService;
        this.profileExtractor = profileExtractor;
        this.coreClient = coreClient;
        this.tokenIssueService = tokenIssueService;
        this.refreshCookieWriter = refreshCookieWriter;
        this.properties = properties;
    }

    public TokenResponse exchange(String provider,
                                  TokenExchangeRequest request,
                                  HttpServletRequest servletRequest,
                                  HttpServletResponse servletResponse) {
        AuthFlowState flowState = authFlowCookieService.read(servletRequest)
                .orElseThrow(() -> new BusinessException(ErrorCode.AUTH_STATE_INVALID));
        if (!flowState.state().equals(request.state())
                || !flowState.registrationId().equals(provider)) {
            throw new BusinessException(ErrorCode.AUTH_STATE_INVALID);
        }
        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId(provider);
        if (registration == null) {
            throw new BusinessException(ErrorCode.AUTH_STATE_INVALID);
        }

        ProviderProfile profile = loadProfile(flowState, registration, request.code());
        long userId = findOrCreateUser(profile);
        TokenIssueService.IssuedTokens tokens =
                tokenIssueService.issueForLogin(String.valueOf(userId), provider, clientIp(servletRequest), servletRequest.getHeader("User-Agent"));

        refreshCookieWriter.write(servletResponse, tokens.refreshToken());
        authFlowCookieService.clear(servletResponse);
        return new TokenResponse(tokens.accessToken().value(), TokenResponse.TOKEN_TYPE_BEARER,
                properties.token().accessTtl().toSeconds());
    }

    /** 제공자 토큰 교환 + UserInfo 프로필 — 실패(잘못된 code·네트워크)는 502로 통일한다 */
    private ProviderProfile loadProfile(AuthFlowState flowState, ClientRegistration registration, String code) {
        OAuth2AuthorizationRequest authorizationRequest = flowState.toAuthorizationRequest(registration);
        OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse.success(code)
                .redirectUri(flowState.redirectUri())
                .state(flowState.state())
                .build();
        OAuth2AccessTokenResponse accessTokenResponse;
        try {
            accessTokenResponse = tokenResponseClient.getTokenResponse(
                    new OAuth2AuthorizationCodeGrantRequest(registration,
                            new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse)));
            return profileExtractor.extract(flowState.registrationId(),
                    oauth2UserService.loadUser(new OAuth2UserRequest(registration, accessTokenResponse.getAccessToken())).getAttributes());
        } catch (OAuth2AuthorizationException | OAuth2AuthenticationException | RestClientException e) {
            throw new BusinessException(ErrorCode.AUTH_PROVIDER_ERROR, e.getMessage(), e);
        }
    }

    /** core get-or-create — 탈퇴 계정(409 USER_WITHDRAWN)은 그대로 전파, 그 외 도메인 4xx는 503으로 */
    private long findOrCreateUser(ProviderProfile profile) {
        GetOrCreateUserResponse user;
        try {
            user = coreClient.getOrCreateUser(profile.provider(), profile.providerUserId(),
                    profile.email(), profile.name());
        } catch (CoreCallException e) {
            if (ErrorCode.USER_WITHDRAWN.getCode().equals(e.getResultCode())) {
                throw new BusinessException(ErrorCode.USER_WITHDRAWN);
            }
            throw new BusinessException(ErrorCode.SERVICE_UNAVAILABLE, e.getMessage(), e);
        }
        return Long.parseLong(user.userId());
    }

    /** X-Forwarded-For 첫 홉(gateway가 appended) — 없으면 remoteAddr */
    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
