package net.java21.crowfoot.auth.token.jwt;

import net.java21.crowfoot.auth.testsupport.MutableClock;
import net.java21.crowfoot.auth.testsupport.TestAuthProperties;
import net.java21.crowfoot.auth.testsupport.TestTokenFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class JwtIssuerTest {

    private MutableClock clock;
    private JwtIssuer jwtIssuer;

    @BeforeEach
    void setUp() {
        clock = MutableClock.atUtc2026();
        jwtIssuer = new JwtIssuer(TestTokenFactory.encoder(), clock, TestAuthProperties.create());
    }

    @Test
    @DisplayName("Access 발급 클레임 계약 — sub·iss·aud·typ·sid·jti(UUID)·exp=now+60m, 이메일·이름 스냅샷 없음")
    void issueAccessTokenClaims() {
        Instant now = clock.instant();

        IssuedToken token = jwtIssuer.issueAccessToken("42", "sid-1");
        var jwt = TestTokenFactory.decoder().decode(token.value());

        assertThat(jwt.getSubject()).isEqualTo("42");
        assertThat(jwt.getIssuer().toString()).isEqualTo("https://crowfoot-api.java21.net");
        assertThat(jwt.getAudience()).containsExactly("crowfoot-web", "crowfoot-sync");
        assertThat(jwt.getClaimAsString("typ")).isEqualTo("ACCESS");
        assertThat(jwt.getClaimAsString("sid")).isEqualTo("sid-1");
        assertThat(jwt.getExpiresAt()).isEqualTo(now.plus(Duration.ofMinutes(60)));
        assertThat(jwt.getIssuedAt()).isEqualTo(now);
        assertThat(jwt.getNotBefore()).isEqualTo(now);
        // jti는 UUID v4 형식
        assertThat(UUID.fromString(jwt.getId())).isNotNull();
        // 클레임에 회원 정보 스냅샷 금지 (requirements 1.4.2)
        assertThat(jwt.getClaims()).doesNotContainKeys("email", "name", "role");
    }

    @Test
    @DisplayName("Refresh 발급 — typ=REFRESH·exp=now+6h(슬라이딩 기준)")
    void issueRefreshTokenClaims() {
        IssuedToken token = jwtIssuer.issueRefreshToken("42", "sid-1");
        var jwt = TestTokenFactory.decoder().decode(token.value());

        assertThat(jwt.getClaimAsString("typ")).isEqualTo("REFRESH");
        assertThat(jwt.getExpiresAt()).isEqualTo(clock.instant().plus(Duration.ofHours(6)));
    }

    @Test
    @DisplayName("jti는 발급마다 상이하다 — Access 2연속 발급 비교")
    void jtiDiffersEachIssue() {
        IssuedToken first = jwtIssuer.issueAccessToken("42", "sid-1");
        IssuedToken second = jwtIssuer.issueAccessToken("42", "sid-1");

        assertThat(first.jti()).isNotEqualTo(second.jti());
    }

    @Test
    @DisplayName("jti 승계 발급(GRACE 재발급) — 지정한 jti가 그대로 들어가고 exp는 now+TTL로 갱신")
    void issueRefreshTokenWithFixedJti() {
        String inheritedJti = UUID.randomUUID().toString();

        IssuedToken token = jwtIssuer.issueRefreshToken("42", "sid-1", inheritedJti);

        assertThat(token.jti()).isEqualTo(inheritedJti);
        assertThat(token.expiresAt()).isEqualTo(clock.instant().plus(Duration.ofHours(6)));
        var jwt = TestTokenFactory.decoder().decode(token.value());
        assertThat(jwt.getId()).isEqualTo(inheritedJti);
    }
}
