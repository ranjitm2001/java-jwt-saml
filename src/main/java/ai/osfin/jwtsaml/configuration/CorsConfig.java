package ai.osfin.jwtsaml.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Configuration
public class CorsConfig implements WebMvcConfigurer {

	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**")
			.allowedOrigins("http://localhost:3000", "https://dev-21824939.okta.com")
			.allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
			.allowedHeaders("Content-Type", "Authorization", "X-Requested-With")
			.exposedHeaders("Access-Control-Allow-Origin")
			.allowCredentials(true)
			.maxAge(3600);
	}

//	@Override
//	public void addInterceptors(InterceptorRegistry registry) {
//		registry.addInterceptor(new HandlerInterceptorAdapter() {
//			@Override
//			public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
//				if (request.getMethod().equals(HttpMethod.OPTIONS.name())) {
//					response.setStatus(HttpStatus.OK.value());
//					response.setHeader("Referrer-Policy", "no-referrer");
//					response.setHeader("Access-Control-Allow-Origin", "https://dev-21824939.okta.com");
//					response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
//					response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
//					return false;
//				}
//				return true;
//			}
//		});
//	}
}
