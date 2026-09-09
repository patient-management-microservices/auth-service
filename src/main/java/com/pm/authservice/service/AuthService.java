package com.pm.authservice.service;

import com.pm.authservice.dto.LoginRequestDTO;
import com.pm.authservice.dto.LoginResponseDTO;
import com.pm.authservice.dto.RegisterRequestDTO;
import com.pm.authservice.dto.RegisterResponseDTO;
import com.pm.authservice.enums.Role;
import com.pm.authservice.exception.EmailAlreadyExistsException;
import com.pm.authservice.model.User;
import com.pm.authservice.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
public class AuthService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    public AuthService(
            UserService userService,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            RefreshTokenService refreshTokenService
    ) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;

    }

    public Optional<LoginResponseDTO> authenticate(LoginRequestDTO loginRequestDTO) {
        String normalizedEmail = loginRequestDTO.email().trim().toLowerCase();
        log.info("Login attempt started for email={}", normalizedEmail);

        Optional<LoginResponseDTO> loginResponse = userService
                .findByEmail(normalizedEmail)
                .filter(user -> passwordEncoder.matches(loginRequestDTO.password(), user.getPasswordHash()))
                .map(user -> {
                    String accessToken = jwtUtil.generateToken(user.getId(), user.getEmail(), user.getRole());
                    String refreshToken = refreshTokenService.createRefreshToken(user.getId());
                    return new LoginResponseDTO(
                            accessToken,
                            refreshToken,
                            "Bearer",
                            jwtUtil.getAccessExpirationMs() / 1000
                    );
                });

        if (loginResponse.isPresent()) {
            log.info("Login successful for email={}", normalizedEmail);
        } else {
            log.warn("Login failed for email={}", normalizedEmail);
        }

        return loginResponse;
    }

    @Transactional
    public RegisterResponseDTO register(RegisterRequestDTO registerRequestDTO) {
        String normalizedEmail = registerRequestDTO.email().trim().toLowerCase();
        log.info("User registration attempt started for email={}", normalizedEmail);

        if (userService.existsByEmail(normalizedEmail)) {
            log.warn("User registration rejected because email already exists: email={}", normalizedEmail);
            throw new EmailAlreadyExistsException(normalizedEmail);
        }

        User savedUser = userService.save(User.builder()
                .email(normalizedEmail)
                .passwordHash(passwordEncoder.encode(registerRequestDTO.password()))
                .role(Role.USER)
                .build());

        log.info("User registration successful for userId={}, email={}, role={}",
                savedUser.getId(), savedUser.getEmail(), savedUser.getRole());

        return new RegisterResponseDTO(savedUser.getId(), savedUser.getEmail(), savedUser.getRole());
    }

}
