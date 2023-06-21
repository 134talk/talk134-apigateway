package kr.co.talk.security;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import java.util.UUID;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class JwtTokenProvider {
    @Value("${jwt.accessToken.secretKey}")
    private String accessTokenKey;

    @Value("${jwt.refreshToken.secretKey}")
    private String refreshTokenKey;

    private final long tokenValidTime = Duration.ofMinutes(30).toMillis(); // 30분

    private final long refreshTokenValidTime = Duration.ofDays(15).toMillis(); // 15일

    // Jwt 토큰 생성
    public String createAccessToken(String userId) {
        Claims claims = Jwts.claims().setSubject(userId);
        Date date = new Date();
        return Jwts.builder()
                .setClaims(claims) // 데이터
                .setIssuedAt(date) // 토큰 발행일자
                .setExpiration(new Date(date.getTime() + tokenValidTime))
//                .signWith(accessTokenKey, SignatureAlgorithm.HS256)
                .signWith(Keys.hmacShaKeyFor(accessTokenKey.getBytes(StandardCharsets.UTF_8)),SignatureAlgorithm.HS256)
                .compact();
    }

    public String createRefreshToken() {
        String uuid = UUID.randomUUID().toString();
        Claims claims = Jwts.claims().setSubject(uuid);
        Date date = new Date();
        return Jwts.builder()
                .setClaims(claims) // 데이터
                .setIssuedAt(date) // 토큰 발행일자
                .setExpiration(new Date(date.getTime() + refreshTokenValidTime))
                .signWith(Keys.hmacShaKeyFor(refreshTokenKey.getBytes(StandardCharsets.UTF_8)),SignatureAlgorithm.HS256)
//                .signWith(refreshTokenKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // subject 값 조회

    public String getAccessTokenSubject(String token) {
        return parseClaims(token, accessTokenKey).getSubject();
    }

    // accessToken 유효성 체크
    public void validAccessToken(String token) {
        parseClaims(token, accessTokenKey);
    }

    private Claims parseClaims(String token, String secretKey) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
//                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException
                | SignatureException | IllegalArgumentException jwtException) {

            log.info("jwtException :: {}", jwtException.getClass());
            throw jwtException;
        }
    }

    /**
     * JWT 토큰의 남은 유효기간을 밀리세컨드 단위로 리턴.
     * @param accessToken 액세스 토큰
     * @return 남은 유효기간 ms
     */
    public long getLeftExpirationMillis(String accessToken) {
        Date expiration = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(accessTokenKey.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseClaimsJws(accessToken)
                .getBody().getExpiration();
        // 만료기간 date에서 현재 date 뺀만큼 ms
        return expiration.getTime() - new Date().getTime();
    }
}
