package com.cos.jwt.controller;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class RestApiController {

	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping("home")
	public String home() {
		System.out.println("home");
		return "<h1>home</h1>";
	}

	@PostMapping("join")
	public String join(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user); // 회원가입 잘됨. 비밀번호 유출 => 시큐리티로 로그인 할 수 없음.
		return "회원가입 완료";
	}

	@GetMapping("/api/v1/user")
	public String user() {
		System.out.println("유저 입장!");
		return "aaa";
	}

	@GetMapping("/api/v1/manager")
	public String manager() {
		return "manager";
	}

	@GetMapping("/api/v1/admin")
	public String admin() {
		return "admin";
	}

}
