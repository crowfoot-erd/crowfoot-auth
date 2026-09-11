package net.java21.crowfoot.auth.token.jwt;

import net.java21.crowfoot.auth.config.AuthProperties;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * HS256 토큰 발급 (02-auth/requirements.md Section 1.4.2) — 클레임은 sub·iss·aud·iat·nbf·exp·jti·typ·sid만.
 * 이메일·이름·역할·권한 스냅샷은 클레임에 넣지 않는다(회원 정보는 core가 단일 소스).
 * jti는 발급마다 UUID v4로 상이하다.
 */
@Component
public class JwtIssuer {

    public static final String TYPE_ACCESS = "ACCESS";
    public static final String TYPE_REFRESH = "REFRESH";
    private static final String CLAIM_TYP = "typ";
    private static final String CLAIM_SID = "sid";

    private final JwtEncoder jwtEncoder;
    private final Clock clock;
    private final AuthProperties properties;

    public JwtIssuer(JwtEncoder jwtEncoder, Clock clock, AuthProperties properties) {
        this.jwtEncoder = jwtEncoder;
        this.clock = clock;
        this.properties = properties;
    }

    /** Access 토큰 — TTL은 정책값(access-ttl, 기본 60m) */
    public IssuedToken issueAccessToken(String sub, String sid) {
        return issue(sub, sid, TYPE_ACCESS, properties.token().accessTtl(), UUID.randomUUID().toString());
    }

    /** Refresh 토큰 — TTL은 정책값(refresh-ttl, 기본 6h·슬라이딩: 재발급마다 now+TTL) */
    public IssuedToken issueRefreshToken(String sub, String sid) {
        return issue(sub, sid, TYPE_REFRESH, properties.token().refreshTtl(), UUID.randomUUID().toString());
    }

    /** Refresh 토큰(jti 승계) — GRACE 재발급: lineage 최신 jti를 유지한 채 now+TTL로 다시 발급 */
    public IssuedToken issueRefreshToken(String sub, String sid, String jti) {
        return issue(sub, sid, TYPE_REFRESH, properties.token().refreshTtl(), jti);
    }

    private IssuedToken issue(String sub, String sid, String typ, Duration ttl, String jti) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(ttl);
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(sub)
                .issuer(properties.token().issuer())
                .audience(properties.token().audience())
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(expiresAt)
                .id(jti)
                .claim(CLAIM_TYP, typ)
                .claim(CLAIM_SID, sid)
                .build();
        String value = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        return new IssuedToken(value, claims.getId(), expiresAt);
    }
}
