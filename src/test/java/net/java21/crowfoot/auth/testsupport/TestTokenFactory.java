package net.java21.crowfoot.auth.testsupport;

import net.java21.crowfoot.auth.config.AuthProperties;
import net.java21.crowfoot.auth.token.jwt.IssuedToken;
import net.java21.crowfoot.auth.token.jwt.JwtIssuer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Clock;
import java.util.Base64;

/**
 * 실제 서명된 토큰을 만드는 테스트 팩토리 — 운영 조립(NimbusJwtEncoder·JwtIssuer)을 그대로 재사용.
 */
public final class TestTokenFactory {

    private final JwtIssuer jwtIssuer;

    public TestTokenFactory(Clock clock) {
        this(clock, TestAuthProperties.create());
    }

    public TestTokenFactory(Clock clock, AuthProperties properties) {
        this.jwtIssuer = new JwtIssuer(encoderFor(properties), clock, properties);
    }

    public IssuedToken access(String sub, String sid) {
        return jwtIssuer.issueAccessToken(sub, sid);
    }

    public IssuedToken refresh(String sub, String sid) {
        return jwtIssuer.issueRefreshToken(sub, sid);
    }

    public IssuedToken refreshWithJti(String sub, String sid, String jti) {
        return jwtIssuer.issueRefreshToken(sub, sid, jti);
    }

    public static SecretKey secretKey() {
        byte[] decoded = Base64.getDecoder().decode(TestAuthProperties.DUMMY_SECRET);
        return new SecretKeySpec(decoded, "HmacSHA256");
    }

    /** 지정 프로퍼티의 jwt 시크릿으로 인코더 — 다른 키로 "위조" 토큰을 만드는 테스트용 */
    public static JwtEncoder encoderFor(AuthProperties properties) {
        byte[] decoded = Base64.getDecoder().decode(properties.jwtSecret());
        return NimbusJwtEncoder.withSecretKey(new SecretKeySpec(decoded, "HmacSHA256")).build();
    }

    public static JwtEncoder encoder() {
        return NimbusJwtEncoder.withSecretKey(secretKey()).build();
    }

    public static JwtDecoder decoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(secretKey())
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        decoder.setJwtValidator(jwt -> org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success());
        return decoder;
    }
}
