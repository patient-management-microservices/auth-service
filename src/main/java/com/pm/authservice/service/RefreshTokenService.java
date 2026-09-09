package com.pm.authservice.service;

import com.pm.authservice.model.RefreshToken;
import com.pm.authservice.model.User;
import com.pm.authservice.repository.RefreshTokenRepository;
import com.pm.authservice.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;
    private final UserService userService;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, JwtUtil jwtUtil, UserService userService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtUtil = jwtUtil;
        this.userService = userService;
    }

    @Transactional
    public String createRefreshToken(UUID userId) {
        String plainToken = jwtUtil.generateRefreshToken();
        String tokenHash = jwtUtil.hashToken(plainToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .userId(userId)
                .tokenHash(tokenHash)
                .expiresAt(Instant.now().plusMillis(jwtUtil.getRefreshExpirationMs()))
                .revoked(false)
                .createdAt(Instant.now())
                .build();

        refreshTokenRepository.save(refreshToken);
        log.debug("Created refresh token for userId={}", userId);
        return plainToken;
    }

    @Transactional
    public Optional<RefreshToken> verifyExpirationAndRevocation(RefreshToken token) {
        if (token.isRevoked()) {
            log.warn("Refresh token is revoked for userId={}", token.getUserId());
            return Optional.empty();
        }

        if (token.getExpiresAt().isBefore(Instant.now())) {
            log.warn("Refresh token was expired for userId={}. Deleting token.", token.getUserId());
            refreshTokenRepository.delete(token);
            return Optional.empty();
        }

        return Optional.of(token);
    }

    @Transactional
    public RefreshResponse processRefreshToken(String requestRefreshToken) {
        String tokenHash = jwtUtil.hashToken(requestRefreshToken);

        Optional<RefreshToken> optionalRefreshToken = refreshTokenRepository.findByTokenHash(tokenHash);

        if (optionalRefreshToken.isEmpty()) {
            log.warn("Refresh token not found in database.");
            throw new JwtException("Invalid refresh token");
        }

        RefreshToken refreshToken = optionalRefreshToken.get();

        if (verifyExpirationAndRevocation(refreshToken).isEmpty()) {
            throw new JwtException("Refresh token is expired or revoked");
        }

        User user = userService.findById(refreshToken.getUserId())
                .orElseThrow(() -> new JwtException("User not found for refresh token"));

        // Rotate the token: delete the old one and create a new one
        refreshTokenRepository.delete(refreshToken);
        String newRefreshToken = createRefreshToken(user.getId());
        String newAccessToken = jwtUtil.generateToken(user.getId(), user.getEmail(), user.getRole());

        log.info("Successfully refreshed tokens for userId={}", user.getId());
        return new RefreshResponse(newAccessToken, newRefreshToken);
    }

    @Transactional
    public void revokeRefreshToken(String requestRefreshToken) {
        String tokenHash = jwtUtil.hashToken(requestRefreshToken);
        refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token -> {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
            log.info("Revoked refresh token for userId={}", token.getUserId());
        });
    }

    @Transactional
    @Scheduled(fixedRateString = "${jwt.refresh-expiration-ms:604800000}")
    public void cleanupExpiredTokens() {
        log.info("Starting cleanup of expired refresh tokens");
        refreshTokenRepository.deleteByExpiresAtBefore(Instant.now());
        log.info("Finished cleanup of expired refresh tokens");
    }

    public record RefreshResponse(String accessToken, String refreshToken) {}
}
