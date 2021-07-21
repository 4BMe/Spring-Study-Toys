package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 필터가 존재함
// login 요청해서 username, password을 post 전송하면
// UsernamePasswordAuthenticationFilter가 동작함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final AuthenticationManager authenticationManager;

	// /login 요청을 하면 로그인 시도를 위해 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");

		// 1. username, password 받아서
		try {
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println(user);
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
					user.getUsername(), user.getPassword());

			// PrincipalDetailsService의 loadUserByUsername() 힘수가 실행됨
			Authentication authentication = authenticationManager.authenticate(authenticationToken);

			// 로그인이 되었다는 뜻
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("로그인 완료됨 :" + principalDetails.getUser().getUsername());

			// authentication 객체를 session에 저장 해야하는데 return하면 Security가 알아서 관리해줌 => 편함
			return authentication;
		} catch (Exception e) {
			e.printStackTrace();
		}

		// 2. 정상인지 로그인 시도를 해보는 것, authenticationManager로 로그인 시도를 하면
		// PrincipalDetailsService가 호출 loadUserByUsername() 힘수가 실행됨

		// 3.PrincipalDetails를 세션에 담고 => Session에 담아야 권한 관리가 가능해짐

		// 4.JWT 토큰을 만들어서 응답
		return null;
	}
	
	// attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication실행
	// JWT 토큰을 만들어서 request요청한 사용자에게 response해주면 됨.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행!!");
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

		String jwtToken = JWT.create()
				.withSubject(principalDetails.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+60000*10))
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512("mfabfeitat"));
		
		response.addHeader("Authorization", "Bearer "+jwtToken);
	}
	
	
}
