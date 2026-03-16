package org.meisl.keycloak.base.ui.view;

import com.vaadin.flow.component.html.IFrame;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Menu;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.auth.AnonymousAllowed;

@Route("swagger-ui")
@Menu(order = 999, icon = "vaadin:info-circle", title = "Swagger UI")
@AnonymousAllowed
public class SwaggerUiView extends VerticalLayout {

    public SwaggerUiView() {
        IFrame swaggerFrame = new IFrame("http://localhost:123/swagger-ui/index.html");
        swaggerFrame.setWidth("100%");
        swaggerFrame.setHeight("1000px");
        add(swaggerFrame);
        setSizeFull();

    }
}

