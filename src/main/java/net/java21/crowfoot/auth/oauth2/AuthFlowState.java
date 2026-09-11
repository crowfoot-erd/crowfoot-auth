package net.java21.crowfoot.auth.oauth2;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * 로그인 시작~교환 사이의 상태 — 서명된 auth_flow 쿠키에 담긴다 (02-auth/requirements.md Section 1.4.6).
 * 세션 무상태: HttpSession을 쓰지 않고 이 쿠키가 유일한 흐름 상태다.
 *
 * @param state          CSRF 방지 난수(교환 API에서 대조)
 * @param codeVerifier   PKCE code_verifier — GitHub OAuth App은 미지원(null), Google 추가 시 사용
 * @param registrationId OAuth2 등록 아이디(github·google)
 * @param redirectUri    GitHub 앱에 등록된 프론트 콜백(교환 시 재전송)
 * @param scopes         요청 스코프
 */
public record AuthFlowState(
        String state,
        String codeVerifier,
        String registrationId,
        String redirectUri,
        Set<String> scopes
) {

    /**
     * 쿠키 상태 → authorize 요청 재조립 — 시작(302 URL 생성)과 교환(token 요청)이 같은 형상을 쓴다.
     * code_verifier가 있으면 S256 code_challenge를 계산해 attributes에 함께 싣는다
     * (DefaultAuthorizationCodeTokenResponseClient가 attributes의 code_verifier를 token 요청에 첨부한다).
     */
    public OAuth2AuthorizationRequest toAuthorizationRequest(ClientRegistration registration) {
        Map<String, Object> attributes = new HashMap<>();
        if (codeVerifier != null) {
            attributes.put(PkceParameterNames.CODE_VERIFIER, codeVerifier);
            attributes.put(PkceParameterNames.CODE_CHALLENGE, s256(codeVerifier));
            attributes.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
        }
        return OAuth2AuthorizationRequest.authorizationCode()
                .clientId(registration.getClientId())
                .authorizationUri(registration.getProviderDetails().getAuthorizationUri())
                .redirectUri(redirectUri)
                .scopes(scopes)
                .state(state)
                .attributes(attributes)
                .build();
    }

    private static String s256(String codeVerifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 미지원", e);
        }
    }
}
