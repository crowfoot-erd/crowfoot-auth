package net.java21.crowfoot.auth.token.jwt;

import net.java21.crowfoot.auth.config.AuthProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.stereotype.Component;

import java.time.Clock;

/**
 * Access 토큰 검증 (introspection 하위) — 서명·exp(스큐)·iss·aud·typ=ACCESS 4항목.
 * 검증 내부 사유는 대분류(EXPIRED/INVALID)까지만 분류해 노출한다. Refresh 토큰은 INVALID 처리된다.
 */
@Component
public class AccessTokenValidator {

    private final JwtDecoder jwtDecoder;
    private final JwtDecoder lenientJwtDecoder;
    private final Clock clock;
    private final AuthProperties properties;

    public AccessTokenValidator(@Qualifier("jwtDecoder") JwtDecoder jwtDecoder,
                                @Qualifier("lenientJwtDecoder") JwtDecoder lenientJwtDecoder,
                                Clock clock,
                                AuthProperties properties) {
        this.jwtDecoder = jwtDecoder;
        this.lenientJwtDecoder = lenientJwtDecoder;
        this.clock = clock;
        this.properties = properties;
    }

    public TokenCheck check(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            if (!JwtIssuer.TYPE_ACCESS.equals(jwt.getClaimAsString("typ"))) {
                return TokenCheck.inactive(InactiveReason.INVALID);
            }
            return TokenCheck.active(jwt);
        } catch (JwtValidationException e) {
            return TokenCheck.inactive(expired(token));
        } catch (JwtException | IllegalArgumentException e) {
            return TokenCheck.inactive(InactiveReason.INVALID);
        }
    }

    /**
     * 만료 분류 — JwtTimestampValidator의 에러 코드는 다른 위반(iss·aud)과 같은 invalid_token이라
     * 문구로 구분하지 않고, 서명만 재검증(lenient)해 exp가 스큐 반영 시점보다 지났는지 직접 본다.
     */
    private InactiveReason expired(String token) {
        try {
            Jwt jwt = lenientJwtDecoder.decode(token);
            boolean expired = jwt.getExpiresAt() != null && jwt.getExpiresAt()
                    .minus(properties.token().clockSkew())
                    .isBefore(clock.instant());
            return expired ? InactiveReason.EXPIRED : InactiveReason.INVALID;
        } catch (JwtException | IllegalArgumentException e) {
            return InactiveReason.INVALID;
        }
    }

    /**
     * 검증 결과 — active이면 jwt에 클레임이 담기고, inactive이면 사유만 담긴다.
     */
    public record TokenCheck(Jwt jwt, InactiveReason inactiveReason) {

        static TokenCheck active(Jwt jwt) {
            return new TokenCheck(jwt, null);
        }

        static TokenCheck inactive(InactiveReason reason) {
            return new TokenCheck(null, reason);
        }

        public boolean active() {
            return inactiveReason == null;
        }
    }
}
