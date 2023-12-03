package com.ricsanfre.security.auth;

import com.ricsanfre.security.jwt.JwtService;
import com.ricsanfre.security.token.Token;
import com.ricsanfre.security.token.TokenRepository;
import com.ricsanfre.security.token.TokenType;
import com.ricsanfre.security.user.Role;
import com.ricsanfre.security.user.User;
import com.ricsanfre.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {

        User user = User
                .builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        // Save user into DB
        User savedUser = userRepository.save(user);
        // Generate Access JWT token
        String jwtToken = jwtService.issueToken(user);
        // Generate Refresh JWT token
        String refreshToken = jwtService.issueRefreshToken(user);

        // Save user Token into DB
        saveUserToken(savedUser, jwtToken);

        // Include jwt Tokens (access and refresh) in the Response
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        // Authenticate user
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        // Get user from DB
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        // Generate JWT tokens
        String jwtToken = jwtService.issueToken(user);
        String refreshToken = jwtService.issueRefreshToken(user);

        // revoke existing tokens in DB
        revokeAllUserTokens(user);
        // Save token into DB
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();

    }

    private void saveUserToken(User savedUser, String jwtToken) {
        Token token = Token.builder()
                .user(savedUser)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        // Save token into DB
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        List<Token> validUserTokens = tokenRepository.findAllValidTokensByUserId(user.getId());

        if (validUserTokens.isEmpty()) {
            return;
        }
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);


    }

    public AuthenticationResponse refreshToken(String authHeader) {
        final String refreshToken;
        final String userEmail;

        if (authHeader == null || authHeader.startsWith("Bearer ")) {
            // Get token: removing "Bearer " string
            refreshToken = authHeader.substring(7);
            // Get user email from token
            userEmail = jwtService.getSubject(refreshToken);
            if (userEmail != null) {
                // Get User details from DB
                User user = this.userRepository.findByEmail(userEmail).orElseThrow();
                // Check if token is valid
                if (jwtService.isValidToken(refreshToken, user)) {
                    String accessToken = jwtService.issueToken(user);
                    // revoke existing tokens in DB
                    revokeAllUserTokens(user);
                    // Save token into DB
                    saveUserToken(user, accessToken);
                    return AuthenticationResponse.builder()
                            .accessToken(accessToken)
                            .refreshToken(refreshToken)
                            .build();

                }
            }
        }
        return AuthenticationResponse.builder().build();
    }
}