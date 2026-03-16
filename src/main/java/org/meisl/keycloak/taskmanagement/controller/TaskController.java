package org.meisl.keycloak.taskmanagement.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class TaskController {

    @GetMapping
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello!");
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('user')")
    public ResponseEntity<String> helloUser(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok("Hello From User!");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('admin')")
    public ResponseEntity<String> helloAdmin(@AuthenticationPrincipal Jwt jwt) {
        String preferredUsername = jwt.getClaimAsString("preferred_username");
        String text = "Hello From Admin! You are accessing as user '" + preferredUsername + "'";
        return ResponseEntity.ok(text);
    }
}
