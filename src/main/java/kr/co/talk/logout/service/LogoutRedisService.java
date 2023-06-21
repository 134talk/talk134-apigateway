package kr.co.talk.logout.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Slf4j
@RequiredArgsConstructor
@Service
public class LogoutRedisService {
    private static final String LOGGED_OUT_USER_POSTFIX = "_LOGOUT_";

    private final StringRedisTemplate redisTemplate;

    /**
     * 액세스 토큰을 블랙리스트로 저장
     * @param accessToken 액세스 토큰
     * @param millis 남은 유효기간 밀리세컨드
     */
    public void blockAccessToken(String accessToken, long millis) {
        this.set(accessToken + LOGGED_OUT_USER_POSTFIX, millis / 1000);
    }

    /**
     * 블랙리스트에 저장된 액세스 토큰인지 리턴
     * @param accessToken 액세스 토큰
     * @return 블랙리스트 등록되어 있으면 {@code true}
     */
    public boolean isBlockedAccessToken(String accessToken) {
        return hasKey(accessToken + LOGGED_OUT_USER_POSTFIX);
    }

    private void set(String key, long seconds) {
        redisTemplate.opsForValue().set(key, "", Duration.ofSeconds(seconds));
        log.info("set redis value for {} sec\n{} : {}", seconds, key, "");
    }

    private boolean hasKey(String key) {
        return redisTemplate.opsForValue().getOperations().hasKey(key) == Boolean.TRUE;
    }

}
