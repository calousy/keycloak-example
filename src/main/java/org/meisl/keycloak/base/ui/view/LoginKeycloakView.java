package org.meisl.keycloak.base.ui.view;

import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.auth.AnonymousAllowed;

@Route("login-keycloak")
@AnonymousAllowed
public class LoginKeycloakView extends VerticalLayout implements BeforeEnterObserver {

    @Override
    public void beforeEnter(BeforeEnterEvent beforeEnterEvent) {
        // Redirect to Keycloak-OAuth2 Login
        UI.getCurrent().getPage().setLocation("/oauth2/authorization/keycloak-example");
    }
}

