package com.example.demo;

import java.util.Map;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.support.HttpSessionHandshakeInterceptor;

public class CustomHandshakeInterceptor extends HttpSessionHandshakeInterceptor {
@Override
public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response,
    WebSocketHandler wsHandler, Map<String, Object> attributes) throws Exception {
  System.out.println("beforeHandshake: "+ request.getHeaders());
  return super.beforeHandshake(request, response, wsHandler, attributes);
}
}
