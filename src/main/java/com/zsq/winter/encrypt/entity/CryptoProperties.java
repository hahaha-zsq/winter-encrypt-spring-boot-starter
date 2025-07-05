package com.zsq.winter.encrypt.entity;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * CryptoProperties 类用于存储加密和解密相关的配置属性
 * 该类通过 @ConfigurationProperties 注解绑定配置文件中的属性，前缀为 "winter-crypto"
 * 使用 @Data 注解自动生成 getter 和 setter 方法，简化编码
 */
@Data
@ConfigurationProperties("winter-crypto")
public class CryptoProperties {
    /**
    * 加密密钥
    */
    private String encryptKey;
    /**
    * 解密密钥
    */
    private String DecryptKey;
    /**
     * 偏移量
     */
    private String iv;
    /**
     * 是否打印banner
     */
    private Boolean isPrint = true;
    // ...... 其他的默认的信息，后期可以补充其他的
}
