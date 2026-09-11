package net.java21.crowfoot.auth.introspection;

import net.java21.crowfoot.auth.blacklist.BlacklistStore;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.config.AuthProperties;
import net.java21.crowfoot.auth.config.SecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(InternalAuthController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("test")
@EnableConfigurationProperties(AuthProperties.class)
class InternalAuthControllerWebTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private IntrospectionService introspectionService;

    @MockitoBean
    private BlacklistStore blacklistStore;

    @Test
    @DisplayName("introspect 활성 — 공통 포맷 래핑 + active·sub·jti·sid·exp·inactiveReason null")
    void introspectActive() throws Exception {
        given(introspectionService.introspect("token-value")).willReturn(new IntrospectionResponse(
                true, "42", "jti-1", "sid-1", "ACCESS",
                "https://crowfoot-api.java21.net", "crowfoot-web crowfoot-sync",
                1760000000L, 1760003600L, null));

        mockMvc.perform(post("/internal/auth/introspect")
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .param("token", "token-value"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.header.isSuccessful").value(true))
                .andExpect(jsonPath("$.response.active").value(true))
                .andExpect(jsonPath("$.response.sub").value("42"))
                .andExpect(jsonPath("$.response.jti").value("jti-1"))
                .andExpect(jsonPath("$.response.sid").value("sid-1"))
                .andExpect(jsonPath("$.response.exp").value(1760003600))
                .andExpect(jsonPath("$.response.inactiveReason").doesNotExist());
    }

    @Test
    @DisplayName("introspect 비활성 — 200 + active=false + inactiveReason(무효도 API 실패가 아니다)")
    void introspectInactive() throws Exception {
        given(introspectionService.introspect("expired-token")).willReturn(new IntrospectionResponse(
                false, null, null, null, null, null, null, null, null, "EXPIRED"));

        mockMvc.perform(post("/internal/auth/introspect")
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .param("token", "expired-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.active").value(false))
                .andExpect(jsonPath("$.response.inactiveReason").value("EXPIRED"));
    }

    @Test
    @DisplayName("token 파라미터 누락 — 400 INVALID_REQUEST")
    void introspectMissingToken() throws Exception {
        mockMvc.perform(post("/internal/auth/introspect")
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.header.resultCode").value("INVALID_REQUEST"));
    }

    @Test
    @DisplayName("블랙리스트 저장소 장애 — 503 SERVICE_UNAVAILABLE(fail-closed)")
    void introspectStoreFailure() throws Exception {
        willThrow(new BusinessException(ErrorCode.SERVICE_UNAVAILABLE))
                .given(introspectionService).introspect(any());

        mockMvc.perform(post("/internal/auth/introspect")
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .param("token", "t"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.header.resultCode").value("SERVICE_UNAVAILABLE"));
    }

    @Test
    @DisplayName("세션 블랙리스트 등록 — 204 no-content(멱등)")
    void registerSessionBlacklist() throws Exception {
        mockMvc.perform(post("/internal/auth/blacklists")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sid\":\"sid-1\"}"))
                .andExpect(status().isNoContent());

        verify(blacklistStore).registerSession(any(String.class), any());
    }

    @Test
    @DisplayName("세션 등록 — sid blank면 400 INVALID_REQUEST")
    void registerSessionBlankSid() throws Exception {
        mockMvc.perform(post("/internal/auth/blacklists")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sid\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.header.resultCode").value("INVALID_REQUEST"));
    }

    @Test
    @DisplayName("세션 등록 — 저장소 장애면 503(204로 위장하지 않음)")
    void registerSessionStoreFailure() throws Exception {
        willThrow(new BusinessException(ErrorCode.SERVICE_UNAVAILABLE))
                .given(blacklistStore).registerSession(any(String.class), any());

        mockMvc.perform(post("/internal/auth/blacklists")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sid\":\"sid-1\"}"))
                .andExpect(status().isServiceUnavailable());
    }
}
