package org.meisl.keycloak.security.dev;

import com.vaadin.flow.spring.security.VaadinAwareSecurityContextHolderStrategy;
import com.vaadin.flow.spring.security.VaadinSecurityConfigurer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * Security configuration.
 * <p>
 * This configuration integrates with Vaadin's security framework through {@link VaadinSecurityConfigurer} to provide a
 * seamless login experience in the Vaadin UI.
 * </p>
 *
 */
@EnableWebSecurity
@Configuration
@Import({VaadinAwareSecurityContextHolderStrategy.class})
class DevSecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(DevSecurityConfig.class);

    @Autowired
    private KeycloakOidcUserService keycloakOidcUserService;

    @Autowired
    private ClientRegistrationRepository registrationRepository;

    @Autowired
    private VaadinLoginSuccessHandler vaadinLoginSuccessHandler;

    // Resource Server Security (API)
    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurity(HttpSecurity http) {
        http
                .securityMatcher("/api/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(
                        (oauth2) -> oauth2.jwt(
                                jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())
                        ))
                .csrf(AbstractHttpConfigurer::disable); // API usually stateless

        return http.build();
    }

    // UI Security (Vaadin + OAuth2 Login)
    @Bean
    @Order(2)
    public SecurityFilterChain vaadinSecurityFilterChain(HttpSecurity http) throws Exception {
        http.with(VaadinSecurityConfigurer.vaadin(), Customizer.withDefaults());

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/actuator/health",
                                "/swagger-ui/**",
                                "/v3/api-docs/**").permitAll())

                // SecurityContext im HttpSession speichern (WICHTIG für Vaadin!)
                .securityContext(ctx ->
                        ctx.securityContextRepository(new HttpSessionSecurityContextRepository())
                )

                // Sessions erlauben
                .sessionManagement(sm ->
                        sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )

                .oauth2Login(o ->
                        o.userInfoEndpoint(x -> x.oidcUserService(keycloakOidcUserService))
                                .successHandler(vaadinLoginSuccessHandler)
                )

                .logout(logout -> logout
                        .logoutSuccessHandler(oidcLogoutSuccessHandler())
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID")
                        // Allow Logout for GET request.
                        // Otherwise you would see the Spring Boot Logout confirmation page.
                        .logoutRequestMatcher(PathPatternRequestMatcher.pathPattern(HttpMethod.GET, "/logout"))
                );

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter("example-api"));
        return converter;
    }

    // Dieser Handler sorgt dafür, dass auch die Session bei Keycloak beendet wird
    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(registrationRepository);

        logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");

        return logoutSuccessHandler;
    }
}
