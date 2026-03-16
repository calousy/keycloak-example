package org.meisl.keycloak.taskmanagement.ui.view;

import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Menu;
import com.vaadin.flow.router.Route;
import jakarta.annotation.security.PermitAll;
import org.meisl.keycloak.security.CurrentUser;

@Route("dashboard")
@Menu(order = 20, icon = "vaadin:dashboard", title = "Dashboard")
@PermitAll // Nur für authentifizierte Benutzer (egal welche Rolle)
public class DashboardView extends VerticalLayout {

    public DashboardView(CurrentUser currentUser) {
        add(new Span("Willkommen zurück, " + currentUser.getFullName() + "!"));
    }
}