package net.java21.crowfoot.auth.oauth2;

/**
 * 제공자 프로필 추출 결과 — core get-or-create 요청 재료 (08-core/05-account.md Section 3.1).
 *
 * @param provider       제공자 코드(github·google)
 * @param providerUserId 제공자 내 불변 식별자(GitHub id·Google sub) — 이메일 변경에 영향받지 않는다
 * @param email          이메일(null 허용 — GitHub 공개 이메일 없음 등)
 * @param name           표시명
 */
public record ProviderProfile(String provider, String providerUserId, String email, String name) {
}
