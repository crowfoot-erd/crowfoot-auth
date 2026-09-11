package net.java21.crowfoot.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.List;

/**
 * 토큰 조립 — HS256 단일 시크릿(인증 서버 유일 보관, 02-auth/requirements.md Section 1.4.2~1.4.3).
 * 검증 디코더는 서명 + exp(클럭 스큐 반영) + iss + aud를 검증하고,
 * lenient 디코더는 서명만 검증(클레임 생략) — 로그아웃 블랙리스트 TTL 계산용 만료 토큰 클레임 추출에 쓴다.
 */
@Configuration
public class TokenConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public SecretKey jwtSecretKey(AuthProperties properties) {
        return secretKey(properties.jwtSecret(), "JWT HS256");
    }

    @Bean
    public SecretKey flowSecretKey(AuthProperties properties) {
        return secretKey(properties.flowSecret(), "auth_flow HMAC");
    }

    private static SecretKey secretKey(String base64, String purpose) {
        if (base64 == null || base64.isBlank()) {
            throw new IllegalStateException(purpose + " 시크릿이 설정되지 않았다 — .env / 환경변수를 확인한다");
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(purpose + " 시크릿은 Base64로 인코딩된 값이어야 한다", e);
        }
        if (decoded.length < 32) {
            throw new IllegalStateException(purpose + " 시크릿은 디코딩해 32바이트(256bit) 이상이어야 한다");
        }
        return new SecretKeySpec(decoded, "HmacSHA256");
    }

    @Bean
    public JwtEncoder jwtEncoder(SecretKey jwtSecretKey) {
        // Security 7 — ImmutableSecret 생성자 대신 withSecretKey 빌더
        return NimbusJwtEncoder.withSecretKey(jwtSecretKey).build();
    }

    /** 검증용 디코더 — 서명·exp(스큐)·iss·aud. typ(ACCESS/REFRESH) 판별은 호출측(AccessTokenValidator·RefreshTokenParser) */
    @Bean
    public JwtDecoder jwtDecoder(SecretKey jwtSecretKey, AuthProperties properties, Clock clock) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(jwtSecretKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        List<String> audience = properties.token().audience();
        OAuth2TokenValidator<Jwt> audienceValidator =
                new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                        aud -> aud != null && audience.stream().anyMatch(aud::contains));
        JwtTimestampValidator timestampValidator = new JwtTimestampValidator(properties.token().clockSkew());
        timestampValidator.setClock(clock); // 만료·nbf 판정 기준 시계(테스트는 고정·전진)
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                timestampValidator,
                new JwtIssuerValidator(properties.token().issuer()),
                audienceValidator));
        return decoder;
    }

    /** 서명만 검증하는 디코더 — 만료 토큰에서 jti·exp 추출(로그아웃 블랙리스트 TTL)에 한정해 쓴다 */
    @Bean
    public JwtDecoder lenientJwtDecoder(SecretKey jwtSecretKey) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(jwtSecretKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        // Security 7 — NoOpJwtValidator 폐지, 무조건 성공 validator로 대체
        decoder.setJwtValidator(jwt -> OAuth2TokenValidatorResult.success());
        return decoder;
    }

    /** code→Access 토큰 교환 클라이언트 — Security 7의 RestClient 구현체 */
    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseClient() {
        return new RestClientAuthorizationCodeTokenResponseClient();
    }

    /** UserInfo 프로필 호출 서비스 */
    @Bean
    public DefaultOAuth2UserService oauth2UserService() {
        return new DefaultOAuth2UserService();
    }
}
