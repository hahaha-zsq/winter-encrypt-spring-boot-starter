package com.zsq.winter.encrypt.strategy.impl;

import com.zsq.winter.encrypt.annotation.FieldDecrypt;
import com.zsq.winter.encrypt.annotation.FieldEncrypt;
import com.zsq.winter.encrypt.enums.CollectionStrategyType;
import com.zsq.winter.encrypt.service.CryptoService;
import com.zsq.winter.encrypt.strategy.AbstractCollectionCryptoStrategy;
import lombok.extern.slf4j.Slf4j;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Set集合加密解密策略实现类
 * 
 * <p>专门处理{@link Set}类型的加密解密操作，继承自{@link AbstractCollectionCryptoStrategy}。
 * 使用Stream流处理Set中的每个元素，保持原有的集合结构。</p>
 * 
 * <p>处理流程：</p>
 * <ol>
 *   <li>检查Set是否为null</li>
 *   <li>使用Stream流遍历Set中的每个元素</li>
 *   <li>对每个元素进行加密/解密处理</li>
 *   <li>收集处理后的元素重新构建Set</li>
 * </ol>
 * 
 * <p><strong>注意：</strong>该策略保持Set的无序性和唯一性特性，加密后的元素仍然保持唯一。</p>
 * 
 * @author dadandiaoming
 * @since 1.0.0
 * @see AbstractCollectionCryptoStrategy
 * @see CollectionStrategyType#SET
 */
@Slf4j
public class SetCryptoStrategy extends AbstractCollectionCryptoStrategy {

    /**
     * 加密Set集合（对称加密）
     * 
     * <p>对Set中的每个元素进行对称加密处理，返回包含加密后元素的新Set。
     * 保持Set的无序性和唯一性特性。专门用于AES、DES等对称加密算法。</p>
     *
     * @param collection 待加密的Set集合
     * @param cryptoService 加密服务实例
     * @param annotation 加密注解，包含加密参数配置
     * @param encryptKey 加密密钥
     * @param iv 初始化向量
     * @return 加密后的Set集合，如果输入为null则返回null
     * @throws com.zsq.winter.encrypt.exception.CryptoException 当加密过程中发生错误时抛出
     */
    @Override
    public Object encrypt(Object collection, CryptoService cryptoService,
                          FieldEncrypt annotation, String encryptKey, String iv) {
        if (isNullCollection(collection)) {
            return null;
        }

        logOperation(collection, "对称加密");
        Set<?> set = (Set<?>) collection;
        // 大集合并行加密
        if (set.size() > 50) {
            return set.parallelStream()
                    .map(item -> encryptItem(item, cryptoService, annotation, encryptKey, iv))
                    .collect(Collectors.toSet());
        } else {
            return set.stream()
                    .map(item -> encryptItem(item, cryptoService, annotation, encryptKey, iv))
                    .collect(Collectors.toSet());
        }
    }

    /**
     * RSA加密Set集合
     * 
     * <p>对Set中的每个元素进行RSA加密处理，返回包含加密后元素的新Set。
     * 保持Set的无序性和唯一性特性。专门用于RSA非对称加密算法。</p>
     *
     * @param collection 待加密的Set集合
     * @param cryptoService 加密服务实例
     * @param annotation 加密注解，包含加密参数配置
     * @param privateKey RSA私钥
     * @param publicKey RSA公钥
     * @return 加密后的Set集合，如果输入为null则返回null
     * @throws com.zsq.winter.encrypt.exception.CryptoException 当RSA加密过程中发生错误时抛出
     */
    @Override
    public Object encryptRsa(Object collection, CryptoService cryptoService,
                            FieldEncrypt annotation, String privateKey, String publicKey) {
        if (isNullCollection(collection)) {
            return null;
        }

        logOperation(collection, "RSA加密");
        Set<?> set = (Set<?>) collection;
        
        // 使用Stream流处理Set RSA加密
        return set.stream()
                .map(item -> encryptRsaItem(item, cryptoService, privateKey, publicKey))
                .collect(Collectors.toSet());
    }

    /**
     * 解密Set集合（对称解密）
     * 
     * <p>对Set中的每个加密元素进行对称解密处理，返回包含解密后元素的新Set。
     * 保持Set的无序性和唯一性特性。专门用于AES、DES等对称解密算法。</p>
     *
     * @param collection 待解密的Set集合
     * @param cryptoService 解密服务实例
     * @param annotation 解密注解，包含解密参数配置
     * @param decryptKey 解密密钥
     * @param iv 初始化向量
     * @return 解密后的Set集合，如果输入为null则返回null
     * @throws com.zsq.winter.encrypt.exception.CryptoException 当解密过程中发生错误时抛出
     */
    @Override
    public Object decrypt(Object collection, CryptoService cryptoService,
                          FieldDecrypt annotation, String decryptKey, String iv) {
        if (isNullCollection(collection)) {
            return null;
        }

        logOperation(collection, "对称解密");
        Set<?> set = (Set<?>) collection;
        // 大集合并行解密
        if (set.size() > 50) {
            return set.parallelStream()
                    .map(item -> decryptItem(item, cryptoService, annotation, decryptKey, iv))
                    .collect(Collectors.toSet());
        } else {
            return set.stream()
                    .map(item -> decryptItem(item, cryptoService, annotation, decryptKey, iv))
                    .collect(Collectors.toSet());
        }
    }

    /**
     * RSA解密Set集合
     * 
     * <p>对Set中的每个RSA加密元素进行解密处理，返回包含解密后元素的新Set。
     * 保持Set的无序性和唯一性特性。专门用于RSA非对称解密算法。</p>
     *
     * @param collection 待解密的Set集合
     * @param cryptoService 解密服务实例
     * @param annotation 解密注解，包含解密参数配置
     * @param publicKey RSA公钥
     * @param privateKey RSA私钥
     * @return 解密后的Set集合，如果输入为null则返回null
     * @throws com.zsq.winter.encrypt.exception.CryptoException 当RSA解密过程中发生错误时抛出
     */
    @Override
    public Object decryptRsa(Object collection, CryptoService cryptoService,
                            FieldDecrypt annotation, String publicKey, String privateKey) {
        if (isNullCollection(collection)) {
            return null;
        }

        logOperation(collection, "RSA解密");
        Set<?> set = (Set<?>) collection;
        
        // 使用Stream流处理Set RSA解密
        return set.stream()
                .map(item -> decryptRsaItem(item, cryptoService, publicKey, privateKey))
                .collect(Collectors.toSet());
    }

    /**
     * 获取策略名称
     *
     * @return 策略名称
     */
    @Override
    public String getStrategyName() {
        return "Set集合加密解密策略";
    }

    /**
     * 获取策略类型
     *
     * @return Set策略类型
     */
    @Override
    public CollectionStrategyType getStrategyType() {
        return CollectionStrategyType.SET;
    }
} 