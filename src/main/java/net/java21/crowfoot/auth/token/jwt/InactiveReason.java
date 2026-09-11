package net.java21.crowfoot.auth.token.jwt;

/**
 * introspection 비활성 사유 (02-auth/api.md Section 4.1) — 검증 내부 사유는 대분류까지만 노출한다.
 * EXPIRED: exp 경과(스큐 반영 후) / REVOKED: 블랙리스트(로그아웃·세션 폐기) / INVALID: 서명·구조·typ 불일치
 */
public enum InactiveReason {
    EXPIRED,
    REVOKED,
    INVALID
}
