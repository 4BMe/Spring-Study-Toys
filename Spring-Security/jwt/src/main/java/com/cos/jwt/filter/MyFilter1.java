package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter1 implements Filter {
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;

		//토큰 a
//		if (req.getMethod().equals("POST")) {
//			String headerAuth = req.getHeader("Authorization");
//			System.out.println(headerAuth);
//			
//			if(headerAuth.equals("a")) {
//				chain.doFilter(request, response);
//			} else {
//				System.out.println("필터1!");
//				PrintWriter out = res.getWriter();
//				out.println("인증안됨");
//			}
//		}

	}
}
