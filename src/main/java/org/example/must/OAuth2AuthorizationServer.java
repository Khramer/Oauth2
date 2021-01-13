package org.example.must;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
class OAuth2AuthServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private final AuthenticationManager authenticationManager;

    @Autowired
    private final BCryptPasswordEncoder passwordEncoder;

    public OAuth2AuthServerConfiguration(AuthenticationManager authenticationManager, BCryptPasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        String clientID ="clientapp";

        String clientSecret="123456";

        int accessTokenValidity=700;

        clients
                .inMemory()
                .withClient(clientID)
                .secret(passwordEncoder.encode(clientSecret))
                .authorizedGrantTypes("password")
                .scopes("read", "write")
                .accessTokenValiditySeconds(accessTokenValidity);
    }

    public void configure(AuthorizationServerEndpointsConfigurer endPoint) throws Exception {
        endPoint.authenticationManager(authenticationManager);
    }
}