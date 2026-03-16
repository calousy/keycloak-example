package org.meisl.keycloak.security.dev;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class VaadinLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        // Ursprüngliche URL aus Session
        String redirectUrl = (String) request.getSession().getAttribute("redirectAfterLogin");

        if (redirectUrl != null) {
            // Session Attribut entfernen
            request.getSession().removeAttribute("redirectAfterLogin");
            getRedirectStrategy().sendRedirect(request, response, redirectUrl);
        } else {
            // Fallback: Homepage
            super.onAuthenticationSuccess(request, response, authentication);
        }
    }
}
