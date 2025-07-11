package com.eds.auth.exceptions;

import com.eds.auth.utils.ApiResponse;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    public ResponseEntity<ApiResponse> getResponse(String message, int statusCode) {
        return new ResponseEntity<>(ApiResponse.builder().status("FAILED").message(message).build(), HttpStatusCode.valueOf(statusCode));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse> handleSecurityException(Exception exception) {
        ResponseEntity<ApiResponse> response = null;

        if (exception instanceof BadCredentialsException) {
            response = getResponse(exception.getMessage(), 401);
        }

        if (exception instanceof AccountStatusException) {
            response = getResponse("The account is locked or disabled", 401);
        }

        if (exception instanceof AccessDeniedException) {
            response = getResponse("You are not authorized to access this resource", 403);
        }

        if (exception instanceof SignatureException) {
            response = getResponse("The JWT signature is invalid", 403);
        }

        if (exception instanceof ExpiredJwtException) {
            response = getResponse("The JWT token has expired", 403);
        }

        return response;
    }
}
