package net.java21.crowfoot.auth.token.dto;

/**
 * 토큰 교환 응답 (02-auth/api.md Section 3.2) — Access 토큰은 JSON으로 전달되고
 * Refresh 토큰은 crowfoot_refresh 쿠키(Set-Cookie)로 전달된다.
 *
 * @param accessToken 서명된 Access JWT
 * @param tokenType   고정값 "Bearer"
 * @param expiresIn   Access 토큰 수명(초)
 */
public record TokenResponse(
        String accessToken,
        String tokenType,
        long expiresIn
) {

    public static final String TOKEN_TYPE_BEARER = "Bearer";
}
