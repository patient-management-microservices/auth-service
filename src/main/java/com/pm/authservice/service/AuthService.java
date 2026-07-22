package com.pm.authservice.service;

import com.pm.authservice.dto.LoginRequestDTO;
import com.pm.authservice.dto.LoginResponseDTO;
import com.pm.authservice.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthService(
            UserService userService,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil
    ) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public Optional<LoginResponseDTO> authenticate(LoginRequestDTO loginRequestDTO) {
        String normalizedEmail = loginRequestDTO.email().trim().toLowerCase();

        return userService
                .findByEmail(normalizedEmail)
                .filter(user -> passwordEncoder.matches(loginRequestDTO.password(), user.getPasswordHash()))
                .map(user -> new LoginResponseDTO(
                        jwtUtil.generateToken(user.getId(), user.getEmail(), user.getRole()),
                        "Bearer",
                        jwtUtil.getExpirationMs() / 1000
                ));
    }

    public boolean validateToken(String token) {
        try {
            jwtUtil.validateToken(token);
            return true;
        } catch (JwtException je) {
            return false;
        }
    }

}
