package academy.devdojo.youtube.auth.security.filter;

import academy.devdojo.youtube.core.model.ApplicationUser;
import academy.devdojo.youtube.core.property.JwtConfiguration;
import academy.devdojo.youtube.security.token.creator.TokenCreator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtConfiguration jwtConfiguration;
    private final TokenCreator tokenCreator;

    @Override
    @SneakyThrows
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        log.info("Attempting autenthication...");
        ApplicationUser applicationUser = new ObjectMapper().readValue(request.getInputStream(), ApplicationUser.class);

        if (Optional.ofNullable(applicationUser).isEmpty()) {
            throw new UsernameNotFoundException(String.format("Unable to retrieve the username or password"));
        }

        log.info("Creating the authentication object for the user '{}' and calling UserDetailServiceImpl loadUserByUserName", applicationUser.getUsername());
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(applicationUser.getUsername(),
                        applicationUser.getPassword(), Collections.emptyList());

        usernamePasswordAuthenticationToken.setDetails(applicationUser);
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    @SneakyThrows
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {
        log.info("Authentication has successful for the user '{}', generating JWE token", authResult.getName());

        SignedJWT signedJWT = tokenCreator.createSignedJWT(authResult);
        String encryptToken = tokenCreator.encryptToken(signedJWT);

        log.info("Token generated successfully, adding it to the response header");

        response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, "+jwtConfiguration.getHeader().getName());
        response.addHeader(jwtConfiguration.getHeader().getName(), jwtConfiguration.getHeader().getPrefix() + encryptToken);
    }

}
