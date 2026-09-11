package net.java21.crowfoot.auth.oauth2.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import net.java21.crowfoot.auth.common.ApiResponse;
import net.java21.crowfoot.auth.oauth2.dto.TokenExchangeRequest;
import net.java21.crowfoot.auth.oauth2.service.LoginStartService;
import net.java21.crowfoot.auth.oauth2.service.TokenExchangeService;
import net.java21.crowfoot.auth.token.dto.TokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

/**
 * OAuth2 로그인 (02-auth/api.md Section 3.1~3.2) — 시작(302)과 교환(JSON).
 * 콜백 자체는 프론트(/auth/callback)가 받아, 교환 API로 code·state를 넘긴다.
 * 매핑은 /auth/** — Gateway가 /api/v1 접두사를 제거(stripPrefix 2)하고 전달한다 (api.md Section 1 경로 경계).
 * 쿠키 Path(/api/v1/auth)는 외부(프론트) 기준이므로 그대로 유지한다.
 */
@RestController
@RequestMapping("/auth/oauth2")
public class OAuth2LoginController {

    private final LoginStartService loginStartService;
    private final TokenExchangeService tokenExchangeService;

    public OAuth2LoginController(LoginStartService loginStartService, TokenExchangeService tokenExchangeService) {
        this.loginStartService = loginStartService;
        this.tokenExchangeService = tokenExchangeService;
    }

    /** 로그인 시작 — 302 Location(제공자 authorize URL) + Set-Cookie auth_flow */
    @GetMapping("/{provider}")
    public ResponseEntity<Void> start(@PathVariable String provider, HttpServletResponse response) {
        String authorizeUrl = loginStartService.start(provider, response);
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(authorizeUrl)).build();
    }

    /** 인가 코드 교환 — 200 TokenResponse(Access) + Set-Cookie crowfoot_refresh(Refresh) */
    @PostMapping("/{provider}/token")
    public ResponseEntity<ApiResponse<TokenResponse>> exchange(@PathVariable String provider,
                                                               @Valid @RequestBody TokenExchangeRequest request,
                                                               HttpServletRequest servletRequest,
                                                               HttpServletResponse servletResponse) {
        TokenResponse tokenResponse = tokenExchangeService.exchange(provider, request, servletRequest, servletResponse);
        return ResponseEntity.ok(ApiResponse.success(tokenResponse));
    }
}
