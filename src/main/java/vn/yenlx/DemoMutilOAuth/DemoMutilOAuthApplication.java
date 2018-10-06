package vn.yenlx.DemoMutilOAuth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

@SpringBootApplication
//@EnableOAuth2Client
@EnableAuthorizationServer
public class DemoMutilOAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoMutilOAuthApplication.class, args);
	}
}
