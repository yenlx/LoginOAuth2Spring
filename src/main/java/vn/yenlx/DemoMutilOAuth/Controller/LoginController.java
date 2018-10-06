package vn.yenlx.DemoMutilOAuth.Controller;

import java.security.Principal;

import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@EnableOAuth2Sso
public class LoginController {

	@GetMapping("/user")
	public Principal loginUser(Principal user){
		String a = "yenlx";
		return user;
	}
}
