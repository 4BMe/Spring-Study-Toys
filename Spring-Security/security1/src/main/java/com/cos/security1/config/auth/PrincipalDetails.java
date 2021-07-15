package com.cos.security1.config.auth;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.cos.security1.model.User;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다
// 로그인 진행이 완료가 되면 시큐리티가 가지고 있는 session을 만들어준다.(Security ContexHolder) => 키값을 구분한다는 의미
// Session에 들어갈 수 있는 오브젝트 타입는 Authentication 타입의 객체여야 한다.
// Authentication 안에 User 정보가 있어야 한다.
// User 오브젝트의 타입은 UserDetails 타입의 객체여야 한다.

// Security Session => Authentication => UserDetails(PrincipalDetails)

public class PrincipalDetails implements UserDetails{

	private User user; // 컴포지션
	
	public PrincipalDetails(User user) {
		this.user = user;
	}
	
	// 해당 User의 권한을 리턴하는 곳!
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collect = new ArrayList<>();
		collect.add(new GrantedAuthority() {
			@Override
			public String getAuthority() {
				return user.getRole();
			}
		});
		return collect;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	// 만료된 계정이 아닌지 여부
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	// 계정 잠기지 않았는지 여부
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	// 비밀번호가 1년 지나지 않았는지 여부
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	// 계정 활성화 되었는지 여부
	@Override
	public boolean isEnabled() {
		// 1년동안 회원이 로그인을 안하면 휴먼 계정으로 하기로 함.
		// 현재시간 - 로그인시간 => 1년을 초과하면 return false;
		return true;
	}

}
