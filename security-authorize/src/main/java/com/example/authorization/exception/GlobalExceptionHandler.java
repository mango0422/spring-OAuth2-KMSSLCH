package com.example.authorization.exception;

import com.example.authorization.dto.ApiResponseStatus;
import com.example.authorization.dto.BaseResponseDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<BaseResponseDto<Object>> handleInvalidCredentialsException(InvalidCredentialsException ex) {
        BaseResponseDto<Object> response = new BaseResponseDto<>(ApiResponseStatus.INVALID_CREDENTIALS, null);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    // 필요에 따라 다른 예외 핸들러들도 추가할 수 있습니다.
}
