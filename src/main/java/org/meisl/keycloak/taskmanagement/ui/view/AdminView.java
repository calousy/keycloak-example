package org.meisl.keycloak.taskmanagement.ui.view;

import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Menu;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.theme.lumo.LumoUtility;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.client.RestClient;

@Route("admin")
@Menu(order = 100, icon = "vaadin:user-star", title = "Admin View")
@RolesAllowed("FRONTEND_ADMIN") // Nur Benutzer mit der Rolle "ROLE_ADMIN"
public class AdminView extends VerticalLayout {

    private static final String REGISTRATION_ID = "keycloak-api";

    public AdminView(OAuth2AuthorizedClientManager authorizedClientManager,
                     ClientRegistrationRepository clientRegistrationRepository) {

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID);
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(clientRegistration.getRegistrationId())
                .principal("admin-client")  // beliebiger Principal Name für Client Credentials Flow
                .build();

        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);
        if (authorizedClient != null) {
            String token = authorizedClient.getAccessToken().getTokenValue();
            RestClient restClient = RestClient.create();

            restClient.get()
                    .uri("http://localhost:1234/api/v1/admin")
                    .header("Authorization", "Bearer " + token)
                    .exchange((request, response) -> {
                        if (response.getStatusCode().is2xxSuccessful()) {
                            Span span = new Span("Successful REST call: " + response.bodyTo(String.class));
                            add(span);
                            span.addClassNames(LumoUtility.TextColor.SUCCESS);
                        } else {
                            Span span = new Span("REST call failed: " + response.getStatusText());
                            add(span);
                            span.addClassNames(LumoUtility.TextColor.ERROR);
                        }
                        return null;
                    });
        }

        add(new Span("Top secret: Admins only!"));
    }
}