package net.java21.crowfoot.auth.token.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.java21.crowfoot.auth.common.ApiResponse;
import net.java21.crowfoot.auth.token.dto.TokenResponse;
import net.java21.crowfoot.auth.token.service.LogoutService;
import net.java21.crowfoot.auth.token.service.RefreshTokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 토큰 수명 관리 (02-auth/api.md Section 3.3~3.4) — 재발급은 Refresh 쿠키만, 로그아웃은 멱등.
 * 매핑은 /auth/** — Gateway가 /api/v1 접두사를 제거(stripPrefix 2)하고 전달한다 (api.md Section 1 경로 경계).
 */
@RestController
@RequestMapping("/auth")
public class TokenController {

    private final RefreshTokenService refreshTokenService;
    private final LogoutService logoutService;

    public TokenController(RefreshTokenService refreshTokenService, LogoutService logoutService) {
        this.refreshTokenService = refreshTokenService;
        this.logoutService = logoutService;
    }

    /** 재발급 — 200 TokenResponse(신규 Access) + Set-Cookie crowfoot_refresh(차기 Refresh) */
    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<TokenResponse>> refresh(HttpServletRequest request,
                                                              HttpServletResponse response) {
        return ResponseEntity.ok(ApiResponse.success(refreshTokenService.refresh(request, response)));
    }

    /** 로그아웃 — 200 header-only(응답 본문 없음), 쿠키·Bearer 유무와 무관하게 멱등 */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest request, HttpServletResponse response) {
        logoutService.logout(request, response);
        return ResponseEntity.ok(ApiResponse.success());
    }
}
