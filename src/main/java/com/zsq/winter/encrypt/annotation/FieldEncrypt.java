package com.zsq.winter.encrypt.annotation;

import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import com.zsq.winter.encrypt.enums.CryptoType;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 用于指定字段的加密算法及其相关模式和填充方式的注解
 * 主要用于标记在数据传输或存储过程中需要进行加密处理的字段
 *
 * @see CryptoType 加密算法类型
 * @see Mode 加密模式
 * @see Padding 填充方式
 */
@Target(value = ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface FieldEncrypt {
    /**
     * 指定加密算法类型，默认为AES加密
     *
     * @return 加密算法类型
     */
    CryptoType cryptoType() default CryptoType.AES;

    /**
     * 指定加密模式，默认为ECB模式
     *
     * @return 加密模式
     */
    Mode mode() default Mode.ECB;

    /**
     * 指定填充方式，默认为PKCS5Padding填充
     *
     * @return 填充方式
     */
    Padding padding() default Padding.PKCS5Padding;
}
