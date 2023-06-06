package kr.co.talk.security;

import java.nio.charset.StandardCharsets;
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
//    private Key accessTokenKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
//    private Key refreshTokenKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    @Value("${jwt.accessToken.secretKey}")
    private String accessTokenKey;

    @Value("${jwt.refreshToken.secretKey}")
    private String refreshTokenKey;

    private long tokenValidTime = 1000L * 60 * 30; // 30분

    private long refreshTokenValidTime = 1000L * 60 * 60 * 24 * 15; // 15일

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

    // subject 값 조회
    public String getRefreshTokenSubject(String token) {
        return parseClaims(token, refreshTokenKey).getSubject();
    }

    // accessToken 유효성 체크
    public void validAccessToken(String token) {
        parseClaims(token, accessTokenKey);
    }

    // refreshToken 유효성 체크
    public void validRefreshToken(String refreshToken) {
        parseClaims(refreshToken, refreshTokenKey);
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
}
