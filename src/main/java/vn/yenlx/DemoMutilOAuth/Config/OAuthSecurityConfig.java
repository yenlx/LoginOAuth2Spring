package vn.yenlx.DemoMutilOAuth.Config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.filter.CompositeFilter;

@Configurable
@EnableWebSecurity
@Order(90)
public class OAuthSecurityConfig extends WebSecurityConfigurerAdapter {
	private OAuth2ClientContext oauth2ClientContext;
//	private AuthorizationCodeResourceDetails authorizationCodeResourceDetails;
//	private ResourceServerProperties resourceServerProperties;

	@Bean
	@ConfigurationProperties("google")
	public ClientResources google() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("github")
	public ClientResources github() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("cios")
	public ClientResources cios() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("facebook")
	public ClientResources facebook() {
		return new ClientResources();
	}

	@Autowired
	public void setOauth2ClientContext(OAuth2ClientContext oauth2ClientContext) {
		this.oauth2ClientContext = oauth2ClientContext;
	}

//
//	@Autowired
//	public void setAuthorizationCodeResourceDetails(AuthorizationCodeResourceDetails authorizationCodeResourceDetails) {
//		this.authorizationCodeResourceDetails = authorizationCodeResourceDetails;
//	}
//
//	@Autowired
//	public void setResourceServerProperties(ResourceServerProperties resourceServerProperties) {
//		this.resourceServerProperties = resourceServerProperties;
//	}
//
	/*
	 * This method is for overriding the default AuthenticationManagerBuilder. We
	 * can specify how the user details are kept in the application. It may be in a
	 * database, LDAP or in memory.
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		super.configure(auth);
	}

	/*
	 * This method is for overriding some configuration of the WebSecurity If you
	 * want to ignore some request or request patterns then you can specify that
	 * inside this method.
	 */
	@Override
	public void configure(WebSecurity web) throws Exception {
		super.configure(web);
	}

	/*
	 * This method is used for override HttpSecurity of the web Application. We can
	 * specify our authorization criteria inside this method.
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http
				// Starts authorizing configurations.
				.authorizeRequests()
				// Ignore the "/" and "/index.html"
				.antMatchers("/").permitAll()
				// Authenticate all remaining URLs.
				.anyRequest().permitAll().and()
//				.fullyAuthenticated().and()
				// Setting the logout URL "/logout" - default logout URL.
				.logout()
				// After successful logout the application will redirect to "/" path.
				.logoutSuccessUrl("/").permitAll().and()
				// Setting the filter for the URL "/google/login".
				.addFilterAt(ssoFilter(), BasicAuthenticationFilter.class).csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
	}

//	/* This method for creating filter for OAuth authentication. */
//	private OAuth2ClientAuthenticationProcessingFilter googleFilter() {
//		// Creating the filter for "/google/login" url
//		OAuth2ClientAuthenticationProcessingFilter oAuth2Filter = new OAuth2ClientAuthenticationProcessingFilter(
//				"/google/login");
//		oAuth2Filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler() {
//			@Override
//			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//					Authentication authentication) throws IOException, ServletException {
//				this.setDefaultTargetUrl("/login");
//				super.onAuthenticationSuccess(request, response, authentication);
//			}
//		});
//		// Creating the rest template for getting connected with OAuth service.
//		// The configuration parameters will inject while creating the bean.
//		OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(authorizationCodeResourceDetails,
//				oauth2ClientContext);
//		oAuth2Filter.setRestTemplate(oAuth2RestTemplate);
//
//		// Setting the token service. It will help for getting the token and
//		// user details from the OAuth Service.
//		oAuth2Filter.setTokenServices(new UserInfoTokenServices(resourceServerProperties.getUserInfoUri(),
//				resourceServerProperties.getClientId()));
//
//		return oAuth2Filter;
//	}

//	private OAuth2ClientAuthenticationProcessingFilter googleFilter() {
//		// Creating the filter for "/google/login" url
//		ClientResources client = google();
//		OAuth2ClientAuthenticationProcessingFilter oAuth2Filter = new OAuth2ClientAuthenticationProcessingFilter(
//				"/google/login");
//		oAuth2Filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler() {
//			@Override
//			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//					Authentication authentication) throws IOException, ServletException {
//				this.setDefaultTargetUrl("/login");
//				super.onAuthenticationSuccess(request, response, authentication);
//			}
//		});
//		// Creating the rest template for getting connected with OAuth service.
//		// The configuration parameters will inject while creating the bean.
//		OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(client.getClient(),
//				oauth2ClientContext);
//		oAuth2Filter.setRestTemplate(oAuth2RestTemplate);
//		
//		// Setting the token service. It will help for getting the token and
//		// user details from the OAuth Service.
//		oAuth2Filter.setTokenServices(new UserInfoTokenServices(client.getResource().getUserInfoUri(),
//				client.getClient().getClientId()));
//		
//		return oAuth2Filter;
//	}

	private Filter ssoFilter() {
		CompositeFilter filter = new CompositeFilter();
		List<OAuth2ClientAuthenticationProcessingFilter> filters = new ArrayList<>();
		filters.add(ssoFilter(google(), "/google/login"));
		filters.add(ssoFilter(github(), "/github/login"));
		filters.add(ssoFilter(cios(), "/index-sec.html"));
		filters.add(ssoFilter(facebook(), "/login/facebook"));
		filter.setFilters(filters);
		return filter;
	}

	private OAuth2ClientAuthenticationProcessingFilter ssoFilter(ClientResources client, String path) {
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
		filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler() {
			@Override
			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {
				this.setDefaultTargetUrl("/user");
				super.onAuthenticationSuccess(request, response, authentication);
			}
		});
		OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
		filter.setRestTemplate(template);
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(client.getResource().getUserInfoUri(),
				client.getClient().getClientId());
		tokenServices.setRestTemplate(template);
		filter.setTokenServices(tokenServices);
		return filter;
	}

	class ClientResources {

		@NestedConfigurationProperty
		private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

		@NestedConfigurationProperty
		private ResourceServerProperties resource = new ResourceServerProperties();

		public AuthorizationCodeResourceDetails getClient() {
			return client;
		}

		public ResourceServerProperties getResource() {
			return resource;
		}
	}
}