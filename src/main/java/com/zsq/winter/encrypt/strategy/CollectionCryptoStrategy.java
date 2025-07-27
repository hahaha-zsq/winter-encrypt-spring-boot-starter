package com.zsq.winter.encrypt.strategy;

import com.zsq.winter.encrypt.annotation.FieldDecrypt;
import com.zsq.winter.encrypt.annotation.FieldEncrypt;
import com.zsq.winter.encrypt.service.CryptoService;
import com.zsq.winter.encrypt.enums.CollectionStrategyType;

/**
 * 集合加密解密策略接口
 * 定义集合加密解密的通用接口，使用策略模式实现不同类型的集合处理
 */
public interface CollectionCryptoStrategy {

    /**
     * 加密集合中的元素（对称加密）
     *
     * @param collection 待加密的集合
     * @param cryptoService 加密服务
     * @param annotation 加密注解
     * @param encryptKey 加密密钥
     * @param iv 初始化向量
     * @return 加密后的集合
     */
    Object encrypt(Object collection, CryptoService cryptoService, 
                  FieldEncrypt annotation, String encryptKey, String iv);

    /**
     * RSA加密集合中的元素
     *
     * @param collection 待加密的集合
     * @param cryptoService 加密服务
     * @param annotation 加密注解
     * @param privateKey RSA私钥
     * @param publicKey RSA公钥
     * @return 加密后的集合
     */
    Object encryptRsa(Object collection, CryptoService cryptoService, 
                     FieldEncrypt annotation, String privateKey, String publicKey);

    /**
     * 解密集合中的元素（对称解密）
     *
     * @param collection 待解密的集合
     * @param cryptoService 解密服务
     * @param annotation 解密注解
     * @param decryptKey 解密密钥
     * @param iv 初始化向量
     * @return 解密后的集合
     */
    Object decrypt(Object collection, CryptoService cryptoService, 
                  FieldDecrypt annotation, String decryptKey, String iv);

    /**
     * RSA解密集合中的元素
     *
     * @param collection 待解密的集合
     * @param cryptoService 解密服务
     * @param annotation 解密注解
     * @param publicKey RSA公钥
     * @param privateKey RSA私钥
     * @return 解密后的集合
     */
    Object decryptRsa(Object collection, CryptoService cryptoService, 
                     FieldDecrypt annotation, String publicKey, String privateKey);

    /**
     * 获取策略名称
     *
     * @return 策略名称
     */
    String getStrategyName();

    /**
     * 获取策略类型
     *
     * @return 策略类型枚举
     */
    CollectionStrategyType getStrategyType();
} 