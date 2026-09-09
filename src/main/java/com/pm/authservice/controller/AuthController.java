package com.pm.authservice.controller;

import com.pm.authservice.dto.LoginRequestDTO;
import com.pm.authservice.dto.LoginResponseDTO;
import com.pm.authservice.dto.RegisterRequestDTO;
import com.pm.authservice.dto.RegisterResponseDTO;
import com.pm.authservice.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Slf4j
@RestController
public class AuthController {

    private final AuthService authService;
    private final com.pm.authservice.service.RefreshTokenService refreshTokenService;

    public AuthController(AuthService authService, com.pm.authservice.service.RefreshTokenService refreshTokenService) {
        this.authService = authService;
        this.refreshTokenService = refreshTokenService;
    }

    @Operation(summary = "Generate JWT token on user login")
    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@Valid @RequestBody LoginRequestDTO loginRequestDTO) {

        log.debug("Received login request");
        Optional<LoginResponseDTO> tokenOptional = authService.authenticate(loginRequestDTO);

        // Unauthorized
        return tokenOptional.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());

    }

    @Operation(summary = "Register a new user")
    @PostMapping("/register")
    public ResponseEntity<RegisterResponseDTO> register(@Valid @RequestBody RegisterRequestDTO registerRequestDTO) {
        log.debug("Received registration request");
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(registerRequestDTO));
    }

    @Operation(summary = "Refresh JWT access token")
    @PostMapping("/refresh")
    public ResponseEntity<com.pm.authservice.service.RefreshTokenService.RefreshResponse> refresh(@Valid @RequestBody com.pm.authservice.dto.RefreshTokenRequestDTO requestDTO) {
        log.debug("Received token refresh request");
        return ResponseEntity.ok(refreshTokenService.processRefreshToken(requestDTO.getRefreshToken()));
    }

    @Operation(summary = "Logout user and revoke refresh token")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody com.pm.authservice.dto.RefreshTokenRequestDTO requestDTO) {
        log.debug("Received logout request");
        refreshTokenService.revokeRefreshToken(requestDTO.getRefreshToken());
        return ResponseEntity.ok().build();
    }

}
