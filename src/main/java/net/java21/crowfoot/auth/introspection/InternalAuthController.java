package net.java21.crowfoot.auth.introspection;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import net.java21.crowfoot.auth.blacklist.BlacklistStore;
import net.java21.crowfoot.auth.common.ApiResponse;
import net.java21.crowfoot.auth.common.error.BusinessException;
import net.java21.crowfoot.auth.common.error.ErrorCode;
import net.java21.crowfoot.auth.config.AuthProperties;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 내부 API (02-auth/api.md Section 4) — gateway 전용. 내부망 격리를 신뢰한다(core 대칭).
 * introspect는 공통 포맷으로 감싸고, 블랙리스트 등록은 204 no-content(멱등).
 */
@RestController
@RequestMapping("/internal/auth")
public class InternalAuthController {

    private final IntrospectionService introspectionService;
    private final BlacklistStore blacklistStore;
    private final AuthProperties properties;

    public InternalAuthController(IntrospectionService introspectionService,
                                  BlacklistStore blacklistStore,
                                  AuthProperties properties) {
        this.introspectionService = introspectionService;
        this.blacklistStore = blacklistStore;
        this.properties = properties;
    }

    /** 토큰 검증 — form-urlencoded token={JWT}(gateway 계약). 누락·공백은 400 INVALID_REQUEST */
    @PostMapping(path = "/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ApiResponse<IntrospectionResponse> introspect(
            @RequestParam(value = "token", required = false) String token) {
        if (token == null || token.isBlank()) {
            throw new BusinessException(ErrorCode.INVALID_REQUEST);
        }
        return ApiResponse.success(introspectionService.introspect(token));
    }

    /** 세션 폐기 등록(gateway가 AUTH_SESSION_REVOKED 만났을 때 호출) — 204 멱등, 저장소 장애는 503 */
    @PostMapping("/blacklists")
    public ResponseEntity<Void> registerBlacklist(@Valid @RequestBody BlacklistRequest request) {
        blacklistStore.registerSession(request.sid(), properties.token().accessTtl());
        return ResponseEntity.noContent().build();
    }

    /**
     * @param sid 블랙리스트에 등록할 세션 식별자(bl:sid:{sid})
     */
    public record BlacklistRequest(@NotBlank String sid) {
    }
}
