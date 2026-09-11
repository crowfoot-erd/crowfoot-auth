package net.java21.crowfoot.auth.token.jwt;

import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.config.AuthProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;

/**
 * Refresh 토큰 파싱(재발급·로그아웃) — 쿠키의 토큰을 자격증명으로 검증한다.
 * 만료 → AUTH_TOKEN_EXPIRED(401), 그 외 위반 → AUTH_TOKEN_INVALID(401) — api.md Section 3.3·5.
 */
@Component
public class RefreshTokenParser {

    private final JwtDecoder jwtDecoder;
    private final JwtDecoder lenientJwtDecoder;
    private final Clock clock;
    private final AuthProperties properties;

    public RefreshTokenParser(@Qualifier("jwtDecoder") JwtDecoder jwtDecoder,
                              @Qualifier("lenientJwtDecoder") JwtDecoder lenientJwtDecoder,
                              Clock clock,
                              AuthProperties properties) {
        this.jwtDecoder = jwtDecoder;
        this.lenientJwtDecoder = lenientJwtDecoder;
        this.clock = clock;
        this.properties = properties;
    }

    public RefreshClaims parse(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            if (!JwtIssuer.TYPE_REFRESH.equals(jwt.getClaimAsString("typ"))) {
                throw new BusinessException(ErrorCode.AUTH_TOKEN_INVALID);
            }
            return new RefreshClaims(jwt.getSubject(), jwt.getId(), jwt.getClaimAsString("sid"), jwt.getExpiresAt());
        } catch (JwtValidationException e) {
            throw new BusinessException(expired(token) ? ErrorCode.AUTH_TOKEN_EXPIRED : ErrorCode.AUTH_TOKEN_INVALID);
        } catch (JwtException | IllegalArgumentException e) {
            throw new BusinessException(ErrorCode.AUTH_TOKEN_INVALID);
        }
    }

    /** 만료 분류 — 에러 코드가 위반 전반에서 동일하므로 lenient 재검증 후 exp 직접 비교 (AccessTokenValidator 대칭) */
    private boolean expired(String token) {
        try {
            Jwt jwt = lenientJwtDecoder.decode(token);
            return jwt.getExpiresAt() != null && jwt.getExpiresAt()
                    .minus(properties.token().clockSkew())
                    .isBefore(clock.instant());
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    /** 로그아웃 폐기용 — 서명·typ만 검증하고 만료는 허용한다(만료 직후 jti 회수·DELETE가 목적). */
    public RefreshClaims parseLeniently(String token) {
        try {
            Jwt jwt = lenientJwtDecoder.decode(token);
            if (!JwtIssuer.TYPE_REFRESH.equals(jwt.getClaimAsString("typ"))) {
                throw new BusinessException(ErrorCode.AUTH_TOKEN_INVALID);
            }
            return new RefreshClaims(jwt.getSubject(), jwt.getId(), jwt.getClaimAsString("sid"), jwt.getExpiresAt());
        } catch (JwtException | IllegalArgumentException e) {
            throw new BusinessException(ErrorCode.AUTH_TOKEN_INVALID);
        }
    }

    /** Refresh 클레임 — sub(userId)·jti(저장소 키)·sid(세션 승계)·exp(로그아웃 폐기 판단) */
    public record RefreshClaims(String sub, String jti, String sid, Instant expiresAt) {
    }
}
