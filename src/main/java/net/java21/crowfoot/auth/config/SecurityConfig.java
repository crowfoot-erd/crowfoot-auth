package net.java21.crowfoot.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * 무상태 API 서버 — oauth2Login() 필터체인은 쓰지 않는다(콜백이 프론트로 가서 서버에 도착하지 않음).
 * csrf disable(무상태 + SameSite=Strict + POST-only 경로가 방어), /auth·/internal·health만 개방하고
 * 나머지는 denyAll. CORS는 gateway 단일 진입점이 담당한다.
 * permitAll은 서버 도착 경로 기준(/auth/** — Gateway stripPrefix 2). 쿠키 Path=/api/v1/auth는 외부 기준.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/internal/**").permitAll()
                        .requestMatchers("/actuator/health").permitAll()
                        .anyRequest().denyAll())
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable);
        return http.build();
    }
}
