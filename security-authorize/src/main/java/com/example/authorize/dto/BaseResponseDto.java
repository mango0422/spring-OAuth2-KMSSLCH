package com.example.authorize.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class BaseResponseDto<T> {
    private ResponseStatus status;
    private String message;
    private T data;
}