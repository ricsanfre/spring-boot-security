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
import org.springframework.security.crypto.password.PasswordEncoder;
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
        // Generate JWT token
        String jwtToken = jwtService.issueToken(user);

        // Save user Token into DB
        saveUserToken(savedUser, jwtToken);

        // Include jwt Token in the Response
        return AuthenticationResponse.builder()
                .token(jwtToken)
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
        // Generate JWT token
        String jwtToken = jwtService.issueToken(user);
        // revoke existing tokens in DB
        revokeAllUserTokens(user);
        // Save token into DB
        saveUserToken(user,jwtToken);
        return AuthenticationResponse.builder()
                .token(jwtToken)
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
}
