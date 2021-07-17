package com.cos.security1.config;

import org.springframework.beans.factory.annotation.Autowired;

// Oauth
// 1.코드받기(인증), 2. 엑세스토큰(권한)
// 3.사용자프로필 정보를 가져오고 4-1.그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
// 4-2. 받을 수 있는 정보 외에 추가 정보가 필요하면 추가 정보를 받음

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;

@Configuration // 메모리에 올리기
@EnableWebSecurity // 웹 보안 활성화, 스프링시큐리티 필터(지금 등록하고 있는 필터 = 현재 클래스)가 스피링 필터체인에 등록이 된다.
// filter의 가장 큰 역할은 사용자 요청을 검증하고 필요에 따라 데이터를 추가하거나 변조하는 것
@EnableGlobalMethodSecurity(securedEnabled = true, // secured 어노테이션 활성화
							prePostEnabled = true) // @PreAuthorize, @PostAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;
	
	@Bean // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable(); // csrf 비활성화
		http.authorizeRequests()
			.antMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소!!
			.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
			.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll() // 이외의 페이지는 모두 접권 가능
			.and()
			.formLogin()
			.loginPage("/loginForm")
			.loginProcessingUrl("/login") // /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해 줍니다.
			.defaultSuccessUrl("/")
			.and()
			.oauth2Login()
			.loginPage("/loginForm") // 구글 로그인이 완료되면 코드X, 엑세스 토큰+사용자 프로필정보 O
			.userInfoEndpoint()
			.userService(principalOauth2UserService);
			;
	}
}
