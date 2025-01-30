package com.prezcode.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  @Order(1)
  public SecurityFilterChain authorizationSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfigurer oAuth2AuthorizationServerConfigurer =
        OAuth2AuthorizationServerConfigurer.authorizationServer();
    http.securityMatcher(oAuth2AuthorizationServerConfigurer.getEndpointsMatcher())
        .with(
            oAuth2AuthorizationServerConfigurer,
            authorizationServer -> authorizationServer.oidc(Customizer.withDefaults()))
        .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/login")
        .formLogin(Customizer.withDefaults())
        .csrf(csrf -> csrf.disable()) //CSRF protection not needed for this scenario
        .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
    return http.build();
  }
}
