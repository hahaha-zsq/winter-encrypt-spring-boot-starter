package com.zsq.winter.encrypt.exception;

import lombok.Getter;

/**
 * 统一加密解密异常类
 * 
 * <p>用于表示加密解密过程中的各种异常情况，提供统一的异常处理机制。
 * 该异常类包含详细的错误信息，便于问题定位和调试。</p>
 * 
 * <p>异常包含的信息：</p>
 * <ul>
 *   <li>错误类型（ErrorType）</li>
 *   <li>操作类型（加密/解密）</li>
 *   <li>数据对象</li>
 *   <li>容器对象（可选）</li>
 * </ul>
 * 
 * @author dadandiaoming
 * @since 1.0.0
 */
@Getter
public class CryptoException extends RuntimeException {

    /**
     * 错误类型枚举
     * 
     * <p>定义了加密解密过程中可能出现的各种错误类型。</p>
     */
    @Getter
    public enum ErrorType {
        /** 数据为空错误 */
        EMPTY_DATA("数据不能为null"),
        /** 不支持的容器类型错误 */
        UNSUPPORTED_CONTAINER_TYPE("不支持的容器类型"),
        /** 容器加密解密错误 */
        CONTAINER_CRYPTO_ERROR("容器加密解密错误"),
        /** 密钥格式错误 */
        INVALID_KEY_FORMAT("密钥格式不正确"),
        /** 通用错误 */
        GENERAL_ERROR("通用错误");

        /** 错误描述 */
        private final String description;

        /**
         * 构造函数
         *
         * @param description 错误描述
         */
        ErrorType(String description) {
            this.description = description;
        }
    }

    /** 错误类型 */
    private final ErrorType errorType;
    /** 操作类型（加密/解密） */
    private final String operation;
    /** 数据对象 */
    private final Object data;
    /** 容器对象 */
    private final Object container;

    /**
     * 构造函数
     *
     * @param errorType 错误类型
     * @param operation 操作类型（加密/解密）
     * @param data 数据对象
     */
    public CryptoException(ErrorType errorType, String operation, Object data) {
        super(String.format("%s操作失败：%s", operation, errorType.getDescription()));
        this.errorType = errorType;
        this.operation = operation;
        this.data = data;
        this.container = null;
    }

    /**
     * 构造函数
     *
     * @param errorType 错误类型
     * @param operation 操作类型（加密/解密）
     * @param data 数据对象
     * @param container 容器对象
     */
    public CryptoException(ErrorType errorType, String operation, Object data, Object container) {
        super(String.format("%s操作失败：%s", operation, errorType.getDescription()));
        this.errorType = errorType;
        this.operation = operation;
        this.data = data;
        this.container = container;
    }

    /**
     * 构造函数
     *
     * @param message 异常消息
     * @param errorType 错误类型
     * @param operation 操作类型（加密/解密）
     * @param data 数据对象
     */
    public CryptoException(String message, ErrorType errorType, String operation, Object data) {
        super(message);
        this.errorType = errorType;
        this.operation = operation;
        this.data = data;
        this.container = null;
    }

    /**
     * 构造函数
     *
     * @param message 异常消息
     * @param cause 原因异常
     * @param errorType 错误类型
     * @param operation 操作类型（加密/解密）
     * @param data 数据对象
     */
    public CryptoException(String message, Throwable cause, ErrorType errorType, String operation, Object data) {
        super(message, cause);
        this.errorType = errorType;
        this.operation = operation;
        this.data = data;
        this.container = null;
    }

    /**
     * 构造函数
     *
     * @param message 异常消息
     * @param cause 原因异常
     * @param errorType 错误类型
     * @param operation 操作类型（加密/解密）
     * @param data 数据对象
     * @param container 容器对象
     */
    public CryptoException(String message, Throwable cause, ErrorType errorType, String operation, Object data, Object container) {
        super(message, cause);
        this.errorType = errorType;
        this.operation = operation;
        this.data = data;
        this.container = container;
    }

    /**
     * 创建数据为空异常
     * 
     * <p>当待处理的数据为null时使用此方法创建异常。</p>
     *
     * @param operation 操作类型（加密/解密）
     * @param data 数据对象
     * @return CryptoException实例
     */
    public static CryptoException emptyData(String operation, Object data) {
        return new CryptoException(ErrorType.EMPTY_DATA, operation, data);
    }

    /**
     * 创建不支持的容器类型异常
     * 
     * <p>当遇到不支持的容器类型时使用此方法创建异常。</p>
     *
     * @param operation 操作类型（加密/解密）
     * @param containerType 容器类型名称
     * @param container 容器对象
     * @return CryptoException实例
     */
    public static CryptoException unsupportedContainerType(String operation, String containerType, Object container) {
        return new CryptoException(
            String.format("不支持的容器类型: %s", containerType),
            ErrorType.UNSUPPORTED_CONTAINER_TYPE,
            operation,
            containerType
        );
    }

    /**
     * 创建容器加密解密错误异常
     * 
     * <p>当容器加密解密过程中发生错误时使用此方法创建异常。</p>
     *
     * @param message 错误消息
     * @param cause 原因异常
     * @param operation 操作类型（加密/解密）
     * @param data 数据对象
     * @return CryptoException实例
     */
    public static CryptoException containerCryptoError(String message, Throwable cause, String operation, Object data) {
        return new CryptoException(message, cause, ErrorType.CONTAINER_CRYPTO_ERROR, operation, data);
    }

    /**
     * 创建密钥格式错误异常
     * 
     * <p>当密钥格式不正确时使用此方法创建异常。</p>
     *
     * @param message 错误消息
     * @param operation 操作类型（加密/解密）
     * @param key 密钥对象
     * @return CryptoException实例
     */
    public static CryptoException invalidKeyFormat(String message, String operation, Object key) {
        return new CryptoException(message, ErrorType.INVALID_KEY_FORMAT, operation, key);
    }

    /**
     * 创建通用错误异常
     * 
     * <p>当发生其他类型的错误时使用此方法创建异常。</p>
     *
     * @param message 错误消息
     * @param cause 原因异常
     * @param operation 操作类型（加密/解密）
     * @param data 数据对象
     * @return CryptoException实例
     */
    public static CryptoException generalError(String message, Throwable cause, String operation, Object data) {
        return new CryptoException(message, cause, ErrorType.GENERAL_ERROR, operation, data);
    }
} 