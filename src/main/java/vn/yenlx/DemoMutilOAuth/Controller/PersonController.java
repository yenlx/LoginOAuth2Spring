package vn.yenlx.DemoMutilOAuth.Controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PersonController {

	@GetMapping("/testApi")
	public String test() {
		return "yenlx";
	}
}
