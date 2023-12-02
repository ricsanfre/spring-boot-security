package com.ricsanfre.security.auth;

import com.ricsanfre.security.jwt.JwtService;
import com.ricsanfre.security.user.Role;
import com.ricsanfre.security.user.User;
import com.ricsanfre.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
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
       userRepository.save(user);
       // Generate JWT token
       String jwtToken = jwtService.issueToken(user);
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
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
