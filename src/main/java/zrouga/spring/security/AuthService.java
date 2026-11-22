package zrouga.spring.security;

import java.util.Optional;

import zrouga.spring.security.exception.TokenRefreshException;
import zrouga.spring.security.jwt.JwtUtils;
import zrouga.spring.security.payload.JwtResponse;
import zrouga.spring.security.payload.LoginRequest;
import zrouga.spring.security.payload.MessageResponse;
import zrouga.spring.security.payload.TokenRefreshRequest;
import zrouga.spring.security.payload.TokenRefreshResponse;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final AuthUserProvider userRepository;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    public AuthService(
            AuthenticationManager authenticationManager,
            AuthUserProvider userRepository,
            JwtUtils jwtUtils,
            RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
    }

    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        AuthUser user = userRepository.findById(userDetails.getId())
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with id: " + userDetails.getId()));

        String jwt = jwtUtils.generateJwtToken(userDetails, user);

        refreshTokenService.deleteByUserId(user.getId());

        StoredRefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return new JwtResponse(jwt, refreshToken.token());
    }

    public TokenRefreshResponse refreshtoken(TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        Optional<StoredRefreshToken> refreshTokenOpt = refreshTokenService.findByToken(requestRefreshToken);

        if (refreshTokenOpt.isEmpty()) {
            throw new TokenRefreshException(requestRefreshToken, "Refresh token is not in database!");
        }

        StoredRefreshToken stored = refreshTokenService.verifyExpiration(refreshTokenOpt.get());
        AuthUser user = userRepository.findById(stored.userId())
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with id: " + stored.userId()));

        UserDetailsImpl userDetailsImpl = UserDetailsImpl.build(user);

        String token = jwtUtils.generateJwtToken(userDetailsImpl, user);

        return new TokenRefreshResponse(token, requestRefreshToken);
    }

    public MessageResponse logoutUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || auth instanceof AnonymousAuthenticationToken) {
            return new MessageResponse("No logged-in user. Nothing to log out.");
        }

        Object principal = auth.getPrincipal();
        if (principal instanceof UserDetailsImpl userDetails) {
            refreshTokenService.deleteByUserId(userDetails.getId());
            return new MessageResponse("Log out successful!");
        }

        return new MessageResponse("Unable to identify user. Principal: " + principal.toString());
    }
}
