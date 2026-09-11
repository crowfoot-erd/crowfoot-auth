package net.java21.crowfoot.auth.introspection;

/**
 * Introspection 응답 (02-auth/api.md Section 4.1) — 공통 포맷의 response에 담긴다.
 * 필드 명칭·순서는 gateway {@code IntrospectionApiResponse.Response} 파싱과 정확히 일치해야 한다.
 * active=false여도 API 실패가 아니라 200 + active=false + inactiveReason으로 내려간다.
 *
 * @param active         토큰 활성 여부
 * @param sub            사용자 식별자(BIGINT 문자열) — 활성일 때만
 * @param jti            토큰 식별자
 * @param sid            세션 식별자
 * @param typ            토큰 유형(ACCESS)
 * @param iss            발급자
 * @param aud            수신자 목록(공백 결합 문자열 — gateway 파싱 계약)
 * @param iat            발급 시각(epoch seconds)
 * @param exp            만료 시각(epoch seconds)
 * @param inactiveReason 비활성 사유(EXPIRED/REVOKED/INVALID) — 활성이면 null
 */
public record IntrospectionResponse(
        boolean active,
        String sub,
        String jti,
        String sid,
        String typ,
        String iss,
        String aud,
        Long iat,
        Long exp,
        String inactiveReason
) {
}
