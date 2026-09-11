package net.java21.crowfoot.auth.oauth2;

import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * 제공자별 UserInfo 속성 → {@link ProviderProfile} 추출.
 * GitHub: id(불변)·login·name·email(공개 이메일 없으면 null).
 * Google(자격 증명 수령 후 추가 예정): sub·name·email.
 */
@Component
public class ProviderProfileExtractor {

    public ProviderProfile extract(String registrationId, Map<String, Object> attributes) {
        return switch (registrationId) {
            case "github" -> extractGithub(attributes);
            case "google" -> extractGoogle(attributes);
            default -> throw new IllegalArgumentException("지원하지 않는 제공자: " + registrationId);
        };
    }

    private ProviderProfile extractGithub(Map<String, Object> attributes) {
        Object id = attributes.get("id");
        if (id == null) {
            throw new IllegalStateException("GitHub 프로필에 id가 없다");
        }
        String name = text(attributes.get("name"));
        if (name == null) {
            name = text(attributes.get("login"));
        }
        return new ProviderProfile("github", String.valueOf(id), text(attributes.get("email")), name);
    }

    private ProviderProfile extractGoogle(Map<String, Object> attributes) {
        Object sub = attributes.get("sub");
        if (sub == null) {
            throw new IllegalStateException("Google 프로필에 sub가 없다");
        }
        return new ProviderProfile("google", String.valueOf(sub), text(attributes.get("email")), text(attributes.get("name")));
    }

    private String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
