package net.java21.crowfoot.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.cloud.openfeign.EnableFeignClients;

/**
 * Crowfoot 인증 서버 — OAuth2 로그인·토큰 발급·introspection·Redis 블랙리스트.
 * DB리스(02-auth/requirements.md Section 1.1): 회원·Refresh·감사는 core 내부 API 경유.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
@EnableFeignClients
public class CrowfootAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(CrowfootAuthApplication.class, args);
    }
}
