package com.cos.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.security1.model.User;

// CRUD 함수를 JpaRepository가 들고 있음.
// JpaRepository를 상속했기 때문에 @Repository라는 어노테이션이 없어도 IoC된다. Bean으로 자동 등록
public interface UserRepository extends JpaRepository<User, Integer> {
	// findBy 규칙 -> Username 문법
	// select * from user where username =?
	public User findByUsername(String username); // Jpa Query methods
}
