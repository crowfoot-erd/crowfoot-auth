package net.java21.crowfoot.auth.client;

import net.java21.crowfoot.auth.client.dto.CreateAuditLogRequest;
import net.java21.crowfoot.auth.client.dto.GetOrCreateUserRequest;
import net.java21.crowfoot.auth.client.dto.GetOrCreateUserResponse;
import net.java21.crowfoot.auth.client.dto.ProviderResponse;
import net.java21.crowfoot.auth.client.dto.RegisterRefreshTokenRequest;
import net.java21.crowfoot.auth.client.dto.RotateRefreshTokenRequest;
import net.java21.crowfoot.auth.client.dto.RotateRefreshTokenResponse;
import net.java21.crowfoot.auth.common.ApiResponse;
import net.java21.crowfoot.auth.common.ListApiResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * core 내부 API 전송 — api-design.md Section 11(서버 간 호출은 FeignClient).
 * 기점은 SimpleDiscoveryClient 구성(local 8082 / prod Service DNS), 타임아웃은 yml(connect 1s·read 2s).
 *
 * <p>서비스는 이 인터페이스를 직접 쓰지 않는다 — {@link CoreClient}가 응답 해석·에러 매핑을 담당한다.
 */
@FeignClient(name = "crowfoot-core-api")
public interface CoreFeignClient {

    @PostMapping("/internal/core/users:get-or-create")
    ApiResponse<GetOrCreateUserResponse> getOrCreate(@RequestBody GetOrCreateUserRequest request);

    @PostMapping("/internal/core/refresh-tokens")
    ApiResponse<Void> registerRefreshToken(@RequestBody RegisterRefreshTokenRequest request);

    @PostMapping("/internal/core/refresh-tokens:rotate")
    ApiResponse<RotateRefreshTokenResponse> rotate(@RequestBody RotateRefreshTokenRequest request);

    @DeleteMapping("/internal/core/refresh-tokens/{jti}")
    void revokeRefreshToken(@PathVariable("jti") String jti);

    @DeleteMapping("/internal/core/sessions/{sid}")
    void revokeSession(@PathVariable("sid") String sid);

    @PostMapping("/internal/core/audit-logs")
    ApiResponse<Void> recordAudit(@RequestBody CreateAuditLogRequest request);

    @GetMapping("/internal/core/providers")
    ListApiResponse<ProviderResponse> providers();
}
