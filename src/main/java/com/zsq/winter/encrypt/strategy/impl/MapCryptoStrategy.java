package com.zsq.winter.encrypt.strategy.impl;

import com.zsq.winter.encrypt.annotation.FieldDecrypt;
import com.zsq.winter.encrypt.annotation.FieldEncrypt;
import com.zsq.winter.encrypt.enums.CollectionStrategyType;
import com.zsq.winter.encrypt.service.CryptoService;
import com.zsq.winter.encrypt.strategy.AbstractCollectionCryptoStrategy;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Map映射加密解密策略实现类
 * 
 * <p>专门处理{@link Map}类型的加密解密操作，继承自{@link AbstractCollectionCryptoStrategy}。
 * 使用Stream流处理Map中的每个值，保持原有的键值对结构。</p>
 * 
 * <p>处理流程：</p>
 * <ol>
 *   <li>检查Map是否为null</li>
 *   <li>使用Stream流遍历Map的entrySet</li>
 *   <li>保持键不变，对值进行加密/解密处理</li>
 *   <li>收集处理后的键值对重新构建Map</li>
 * </ol>
 * 
 * <p><strong>注意：</strong>该策略只对Map的值进行加密解密，键保持不变。</p>
 * 
 * @author dadandiaoming
 * @since 1.0.0
 * @see AbstractCollectionCryptoStrategy
 * @see CollectionStrategyType#MAP
 */
@Slf4j
public class MapCryptoStrategy extends AbstractCollectionCryptoStrategy {

    /**
     * 加密Map映射（对称加密）
     * 
     * <p>对Map中的每个值进行对称加密处理，返回包含加密后值的新Map。
     * 键保持不变，只对值进行加密。专门用于AES、DES等对称加密算法。</p>
     *
     * @param collection 待加密的Map映射
     * @param cryptoService 加密服务实例
     * @param annotation 加密注解，包含加密参数配置
     * @param encryptKey 加密密钥
     * @param iv 初始化向量
     * @return 加密后的Map映射，如果输入为null则返回null
     * @throws com.zsq.winter.encrypt.exception.CryptoException 当加密过程中发生错误时抛出
     */
    @Override
    public Object encrypt(Object collection, CryptoService cryptoService,
                          FieldEncrypt annotation, String encryptKey, String iv) {
        if (isNullCollection(collection)) {
            return null;
        }

        logOperation(collection, "对称加密");
        Map<?, ?> map = (Map<?, ?>) collection;
        
        // 使用Stream流处理Map对称加密
        return map.entrySet().stream()
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    entry -> encryptItem(entry.getValue(), cryptoService, annotation, encryptKey, iv),
                    (existing, replacement) -> existing,
                    HashMap::new
                ));
    }

    /**
     * RSA加密Map映射
     * 
     * <p>对Map中的每个值进行RSA加密处理，返回包含加密后值的新Map。
     * 键保持不变，只对值进行RSA加密。专门用于RSA非对称加密算法。</p>
     *
     * @param collection 待加密的Map映射
     * @param cryptoService 加密服务实例
     * @param annotation 加密注解，包含加密参数配置
     * @param privateKey RSA私钥
     * @param publicKey RSA公钥
     * @return 加密后的Map映射，如果输入为null则返回null
     * @throws com.zsq.winter.encrypt.exception.CryptoException 当RSA加密过程中发生错误时抛出
     */
    @Override
    public Object encryptRsa(Object collection, CryptoService cryptoService,
                            FieldEncrypt annotation, String privateKey, String publicKey) {
        if (isNullCollection(collection)) {
            return null;
        }

        logOperation(collection, "RSA加密");
        Map<?, ?> map = (Map<?, ?>) collection;
        
        // 使用Stream流处理Map RSA加密
        return map.entrySet().stream()
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    entry -> encryptRsaItem(entry.getValue(), cryptoService, privateKey, publicKey),
                    (existing, replacement) -> existing,
                    HashMap::new
                ));
    }

    /**
     * 解密Map映射（对称解密）
     * 
     * <p>对Map中的每个加密值进行对称解密处理，返回包含解密后值的新Map。
     * 键保持不变，只对值进行解密。专门用于AES、DES等对称解密算法。</p>
     *
     * @param collection 待解密的Map映射
     * @param cryptoService 解密服务实例
     * @param annotation 解密注解，包含解密参数配置
     * @param decryptKey 解密密钥
     * @param iv 初始化向量
     * @return 解密后的Map映射，如果输入为null则返回null
     * @throws com.zsq.winter.encrypt.exception.CryptoException 当解密过程中发生错误时抛出
     */
    @Override
    public Object decrypt(Object collection, CryptoService cryptoService,
                          FieldDecrypt annotation, String decryptKey, String iv) {
        if (isNullCollection(collection)) {
            return null;
        }

        logOperation(collection, "对称解密");
        Map<?, ?> map = (Map<?, ?>) collection;
        
        // 使用Stream流处理Map对称解密
        return map.entrySet().stream()
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    entry -> decryptItem(entry.getValue(), cryptoService, annotation, decryptKey, iv),
                    (existing, replacement) -> existing,
                    HashMap::new
                ));
    }

    /**
     * RSA解密Map映射
     * 
     * <p>对Map中的每个RSA加密值进行解密处理，返回包含解密后值的新Map。
     * 键保持不变，只对值进行RSA解密。专门用于RSA非对称解密算法。</p>
     *
     * @param collection 待解密的Map映射
     * @param cryptoService 解密服务实例
     * @param annotation 解密注解，包含解密参数配置
     * @param publicKey RSA公钥
     * @param privateKey RSA私钥
     * @return 解密后的Map映射，如果输入为null则返回null
     * @throws com.zsq.winter.encrypt.exception.CryptoException 当RSA解密过程中发生错误时抛出
     */
    @Override
    public Object decryptRsa(Object collection, CryptoService cryptoService,
                            FieldDecrypt annotation, String publicKey, String privateKey) {
        if (isNullCollection(collection)) {
            return null;
        }

        logOperation(collection, "RSA解密");
        Map<?, ?> map = (Map<?, ?>) collection;
        
        // 使用Stream流处理Map RSA解密
        return map.entrySet().stream()
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    entry -> decryptRsaItem(entry.getValue(), cryptoService, publicKey, privateKey),
                    (existing, replacement) -> existing,
                    HashMap::new
                ));
    }

    /**
     * 获取策略名称
     *
     * @return 策略名称
     */
    @Override
    public String getStrategyName() {
        return "Map映射加密解密策略";
    }

    /**
     * 获取策略类型
     *
     * @return Map策略类型
     */
    @Override
    public CollectionStrategyType getStrategyType() {
        return CollectionStrategyType.MAP;
    }
} 