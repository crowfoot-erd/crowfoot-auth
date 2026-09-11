package net.java21.crowfoot.auth.oauth2.controller;

import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.config.SecurityConfig;
import net.java21.crowfoot.auth.oauth2.service.LoginStartService;
import net.java21.crowfoot.auth.oauth2.service.TokenExchangeService;
import net.java21.crowfoot.auth.token.dto.TokenResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.EnabledIf;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.context.annotation.Import;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(OAuth2LoginController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("test")
class OAuth2LoginControllerWebTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private LoginStartService loginStartService;

    @MockitoBean
    private TokenExchangeService tokenExchangeService;

    @Test
    @DisplayName("로그인 시작 — 302 Location(제공자 authorize URL)")
    void startRedirects() throws Exception {
        given(loginStartService.start(any(String.class), any()))
                .willReturn("https://github.com/login/oauth/authorize?state=s1");

        mockMvc.perform(get("/auth/oauth2/github"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location",
                        "https://github.com/login/oauth/authorize?state=s1"));
    }

    @Test
    @DisplayName("비활성 제공자 — 404 RESOURCE_NOT_FOUND(공통 실패 포맷)")
    void startUnknownProvider() throws Exception {
        given(loginStartService.start(any(String.class), any()))
                .willThrow(new BusinessException(ErrorCode.RESOURCE_NOT_FOUND));

        mockMvc.perform(get("/auth/oauth2/gitlab"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.header.isSuccessful").value(false))
                .andExpect(jsonPath("$.header.resultCode").value("RESOURCE_NOT_FOUND"))
                .andExpect(jsonPath("$.response").doesNotExist());
    }

    @Test
    @DisplayName("교환 성공 — 200 공통 포맷 + accessToken·tokenType·expiresIn")
    void exchangeSuccess() throws Exception {
        given(tokenExchangeService.exchange(any(String.class), any(), any(), any()))
                .willReturn(new TokenResponse("access-value", "Bearer", 3600L));

        mockMvc.perform(post("/auth/oauth2/github/token")
                        .contentType(APPLICATION_JSON)
                        .content("{\"code\":\"c\",\"state\":\"s\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.header.isSuccessful").value(true))
                .andExpect(jsonPath("$.response.accessToken").value("access-value"))
                .andExpect(jsonPath("$.response.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.response.expiresIn").value(3600));
    }

    @Test
    @DisplayName("code·state blank — 400 INVALID_REQUEST(검증)")
    void exchangeBlankFields() throws Exception {
        mockMvc.perform(post("/auth/oauth2/github/token")
                        .contentType(APPLICATION_JSON)
                        .content("{\"code\":\"\",\"state\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.header.resultCode").value("INVALID_REQUEST"));
    }

    @Test
    @DisplayName("state 불일치 — 400 AUTH_STATE_INVALID")
    void exchangeStateInvalid() throws Exception {
        given(tokenExchangeService.exchange(any(String.class), any(), any(), any()))
                .willThrow(new BusinessException(ErrorCode.AUTH_STATE_INVALID));

        mockMvc.perform(post("/auth/oauth2/github/token")
                        .contentType(APPLICATION_JSON)
                        .content("{\"code\":\"c\",\"state\":\"wrong\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.header.resultCode").value("AUTH_STATE_INVALID"));
    }

    @Test
    @DisplayName("제공자 교환 실패 — 502 AUTH_PROVIDER_ERROR")
    void exchangeProviderError() throws Exception {
        given(tokenExchangeService.exchange(any(String.class), any(), any(), any()))
                .willThrow(new BusinessException(ErrorCode.AUTH_PROVIDER_ERROR));

        mockMvc.perform(post("/auth/oauth2/github/token")
                        .contentType(APPLICATION_JSON)
                        .content("{\"code\":\"c\",\"state\":\"s\"}"))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.header.resultCode").value("AUTH_PROVIDER_ERROR"));
    }

    @Test
    @DisplayName("탈퇴 계정 — 409 USER_WITHDRAWN")
    void exchangeWithdrawnUser() throws Exception {
        given(tokenExchangeService.exchange(any(String.class), any(), any(), any()))
                .willThrow(new BusinessException(ErrorCode.USER_WITHDRAWN));

        mockMvc.perform(post("/auth/oauth2/github/token")
                        .contentType(APPLICATION_JSON)
                        .content("{\"code\":\"c\",\"state\":\"s\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.header.resultCode").value("USER_WITHDRAWN"));
    }
}
