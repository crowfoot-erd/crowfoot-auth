package net.java21.crowfoot.auth.token.controller;

import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.config.SecurityConfig;
import net.java21.crowfoot.auth.token.dto.TokenResponse;
import net.java21.crowfoot.auth.token.service.LogoutService;
import net.java21.crowfoot.auth.token.service.RefreshTokenService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(TokenController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("test")
class TokenControllerWebTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private RefreshTokenService refreshTokenService;

    @MockitoBean
    private LogoutService logoutService;

    @Test
    @DisplayName("재발급 성공 — 200 공통 포맷 + 신규 Access")
    void refreshSuccess() throws Exception {
        given(refreshTokenService.refresh(any(), any()))
                .willReturn(new TokenResponse("new-access", "Bearer", 3600L));

        mockMvc.perform(post("/auth/refresh-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.header.isSuccessful").value(true))
                .andExpect(jsonPath("$.response.accessToken").value("new-access"));
    }

    @Test
    @DisplayName("재발급 — 쿠키 부재·무효면 401 AUTH_TOKEN_INVALID")
    void refreshInvalidToken() throws Exception {
        given(refreshTokenService.refresh(any(), any()))
                .willThrow(new BusinessException(ErrorCode.AUTH_TOKEN_INVALID));

        mockMvc.perform(post("/auth/refresh-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.header.resultCode").value("AUTH_TOKEN_INVALID"));
    }

    @Test
    @DisplayName("재발급 — 만료면 401 AUTH_TOKEN_EXPIRED(코드 구분)")
    void refreshExpiredToken() throws Exception {
        given(refreshTokenService.refresh(any(), any()))
                .willThrow(new BusinessException(ErrorCode.AUTH_TOKEN_EXPIRED));

        mockMvc.perform(post("/auth/refresh-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.header.resultCode").value("AUTH_TOKEN_EXPIRED"));
    }

    @Test
    @DisplayName("재발급 — 세션 폐기(재사용 감지)면 401 AUTH_SESSION_REVOKED")
    void refreshRevokedSession() throws Exception {
        given(refreshTokenService.refresh(any(), any()))
                .willThrow(new BusinessException(ErrorCode.AUTH_SESSION_REVOKED));

        mockMvc.perform(post("/auth/refresh-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.header.resultCode").value("AUTH_SESSION_REVOKED"));
    }

    @Test
    @DisplayName("로그아웃 — 200 header-only(응답 본문 없음), 쿠키·Bearer 유무 무관 멱등")
    void logoutIsHeaderOnly() throws Exception {
        mockMvc.perform(post("/auth/logout"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.header.isSuccessful").value(true))
                .andExpect(jsonPath("$.header.resultCode").value("SUCCESS"))
                .andExpect(jsonPath("$.response").doesNotExist());
    }

    @Test
    @DisplayName("로그아웃 — 폐기 중 core 장애면 503 전파(성공으로 위장하지 않음)")
    void logoutCoreFailure() throws Exception {
        willThrow(new BusinessException(ErrorCode.SERVICE_UNAVAILABLE))
                .given(logoutService).logout(any(), any());

        mockMvc.perform(post("/auth/logout"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.header.resultCode").value("SERVICE_UNAVAILABLE"));
    }
}
