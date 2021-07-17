package com.cos.security1.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@Autowired
	private UserRepository userRepository;

	// 구글로 부터 받은 userRequest 데이터에 대한 후처리 함수
	// 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("getClientRegistration: " + userRequest.getClientRegistration());// registrationId로 어떤 OAuth를
																							// 이용했는지 알 수 있음
		System.out.println("getTokenValue: " + userRequest.getAccessToken().getTokenValue());

		OAuth2User oAuth2User = super.loadUser(userRequest);
		// 구글 로그인 버튼 클릭 -> 구글로그인창 -> 로그인 완료 -> code를 리턴(OAuth-Client라이브러리가 받아줌) ->
		// AccessToken 요청
		// userRequest정보 -> loadUser함수 호출 -> 구글로부터 회원프로필을 받아준다.
		System.out.println("getAttributes: " + super.loadUser(userRequest).getAttributes());

		String provider = userRequest.getClientRegistration().getClientId(); // google
		String providerId = oAuth2User.getAttribute("sub");
		String username = provider + "_" + providerId; // google_sub -> 충돌 날 일이 없음
		String password = bCryptPasswordEncoder.encode("겟인데어");
		String email = oAuth2User.getAttribute("email");
		String role = "ROLE_USER";

		User userEntity = userRepository.findByUsername(username);
		if (userEntity == null) {
			userEntity = User.builder()
					.username(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			userRepository.save(userEntity);
		}

		return new PrincipalDetails(userEntity,oAuth2User.getAttributes());
	}
}
