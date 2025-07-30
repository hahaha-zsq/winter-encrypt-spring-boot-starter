package com.zsq.winter.encrypt.service.impl;

import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import com.zsq.winter.encrypt.enums.CryptoType;
import com.zsq.winter.encrypt.exception.CryptoException;
import com.zsq.winter.encrypt.service.CryptoService;
import com.zsq.winter.encrypt.util.CryptoUtil;
import com.zsq.winter.encrypt.util.CryptoValidator;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * 默认加密解密服务实现类
 *
 * <p>实现了{@link CryptoService}接口，提供了DES和AES加密解密的具体实现。
 * 该实现基于{@link CryptoUtil}工具类，支持多种加密模式和填充方式。</p>
 *
 * <p>支持的加密类型：</p>
 * <ul>
 *   <li>{@link CryptoType#AES} - AES加密算法（默认）</li>
 *   <li>{@link CryptoType#DES} - DES加密算法</li>
 *   <li>{@link CryptoType#RSA} - RSA非对称加密算法</li>
 * </ul>
 *
 * <p>支持的加密模式：</p>
 * <ul>
 *   <li>ECB - 电子密码本模式</li>
 *   <li>CBC - 密码分组链接模式</li>
 *   <li>CFB - 密文反馈模式</li>
 *   <li>OFB - 输出反馈模式</li>
 *   <li>CTR - 计数器模式</li>
 * </ul>
 *
 * <p><strong>密钥和IV长度要求：</strong></p>
 * <ul>
 *   <li><strong>AES</strong>：密钥长度128位(16字节)、192位(24字节)、256位(32字节)，IV长度128位(16字节)</li>
 *   <li><strong>DES</strong>：密钥长度64位(8字节)，IV长度64位(8字节)</li>
 *   <li><strong>RSA</strong>：仅支持Base64格式密钥，不需要IV</li>
 * </ul>
 *
 * @author dadandiaoming
 * @see CryptoService
 * @see CryptoUtil
 * @see CryptoType
 * @since 1.0.0
 */
public class CryptoDefaultServiceImpl implements CryptoService {
    /**
     * DES/AES加密数据
     *
     * <p>根据指定的加密类型、模式、填充方式、密钥和初始化向量对内容进行加密。
     * 支持AES和DES两种加密算法，自动处理不同算法的密钥和IV长度要求。</p>
     *
     * @param mode    加密模式，如ECB、CBC、CFB等
     * @param padding 填充方式，如PKCS5Padding、NoPadding等
     * @param content 待加密的内容
     * @param key     加密密钥
     * @param iv      初始化向量，某些模式需要
     * @param type    加密类型，决定使用DES还是AES加密
     * @return 加密后的十六进制字符串
     * @throws CryptoException  如果参数为null或无效
     * @throws RuntimeException 如果加密失败
     */
    @Override
    public String encrypt(Mode mode, Padding padding, String content, String key, String iv, CryptoType type) {
        // 参数校验
        validateEncryptParams(content, type);

        // 密钥和IV长度校验
        CryptoValidator.validateKeyLength(key, type);
        CryptoValidator.validateIvLength(iv, type);
        String str = "";
        // 根据加密类型调用相应的加密方法
        if (type == CryptoType.DES) {// 使用DES算法进行加密
            str = CryptoUtil.winterDesEncryptHex(mode, padding, key.getBytes(StandardCharsets.UTF_8), iv.getBytes(StandardCharsets.UTF_8), content);
        } else {// 默认使用AES算法进行加密
            str = CryptoUtil.winterAesEncryptHex(mode, padding, key.getBytes(StandardCharsets.UTF_8), iv.getBytes(StandardCharsets.UTF_8), content);
        }
        return str;
    }

    /**
     * DES/AES解密数据
     *
     * <p>根据指定的解密类型、模式、填充方式、密钥和初始化向量对内容进行解密。
     * 支持AES和DES两种解密算法，自动处理不同算法的密钥和IV长度要求。</p>
     *
     * @param mode    解密模式，必须与加密时使用的模式相同
     * @param padding 填充方式，必须与加密时使用的填充方式相同
     * @param content 待解密的内容
     * @param key     解密密钥，必须与加密时使用的密钥相同
     * @param iv      初始化向量，必须与加密时使用的初始化向量相同
     * @param type    解密类型，必须与加密时使用的类型相同
     * @return 解密后的原始字符串
     * @throws CryptoException  如果参数为null或无效
     * @throws RuntimeException 如果解密失败
     */
    @Override
    public String decrypt(Mode mode, Padding padding, String content, String key, String iv, CryptoType type) {
        // 参数校验
        validateDecryptParams(content, key, iv, type);

        // 密钥和IV长度校验（RSA不需要IV验证）
        CryptoValidator.validateKeyLength(key, type);
        CryptoValidator.validateIvLength(iv, type);

        String str = "";
        // 根据解密类型调用相应的解密方法
        if (Objects.requireNonNull(type) == CryptoType.DES) {// 使用DES算法进行解密
            str = CryptoUtil.winterDesDecryptStr(mode, padding, key.getBytes(StandardCharsets.UTF_8), iv.getBytes(StandardCharsets.UTF_8), content);
        } else {// 默认使用AES算法进行解密
            str = CryptoUtil.winterAesDecryptStr(mode, padding, key.getBytes(StandardCharsets.UTF_8), iv.getBytes(StandardCharsets.UTF_8), content);
        }
        return str;
    }

    /**
     * RSA加密数据的方法
     *
     * @param content    待加密的内容，即原始数据
     * @param privateKey RSA私钥（不再使用）
     * @param publicKey  RSA公钥（Base64字符串）
     * @return 返回加密后的Base64字符串
     * @throws CryptoException 如果参数为null或密钥格式不正确
     */
    @Override
    public String encryptRsa(String content, String privateKey, String publicKey) {
        if (content == null) {
            throw CryptoException.emptyData("RSA加密", null);
        }
        if (publicKey == null || publicKey.trim().isEmpty()) {
            throw CryptoException.generalError("RSA公钥不能为空", null, "RSA加密", publicKey);
        }
        // 只用公钥加密
        return CryptoUtil.rsaEncryptToBase64(content, publicKey);
    }

    /**
     * RSA解密数据的方法
     *
     * @param content    待解密的内容（Base64密文）
     * @param publicKey  RSA公钥（不再使用）
     * @param privateKey RSA私钥（Base64字符串）
     * @return 返回解密后的明文
     * @throws CryptoException 如果参数为null或密钥格式不正确
     */
    @Override
    public String decryptRsa(String content, String publicKey, String privateKey) {
        if (content == null || content.trim().isEmpty()) {
            throw CryptoException.emptyData("RSA解密", content);
        }
        if (privateKey == null || privateKey.trim().isEmpty()) {
            throw CryptoException.generalError("RSA私钥不能为空", null, "RSA解密", privateKey);
        }
        // 只用私钥解密
        return CryptoUtil.rsaDecryptFromBase64(content, privateKey);
    }

    /**
     * 获取实际的RSA密钥，兼容旧版配置
     * 
     * @param key 密钥内容
     * @param keyType 密钥类型（用于错误提示）
     * @return 实际密钥内容
     */
    private String getActualRsaKey(String key, String keyType) {
        if (key == null || key.trim().isEmpty()) {
            throw CryptoException.generalError("RSA " + keyType + " 不能为空", null, "RSA加密解密", key);
        }
        return key;
    }

    /**
     * 验证加密参数
     *
     * @param content 待加密内容
     * @param type    加密类型
     */
    private void validateEncryptParams(String content, CryptoType type) {
        if (content == null) {
            throw CryptoException.emptyData("加密", content);
        }
        if (type == null) {
            throw CryptoException.generalError("加密类型不能为null", null, "加密", type);
        }
    }

    /**
     * 验证解密参数
     *
     * @param content 待解密内容
     * @param key     密钥
     * @param iv      初始化向量
     * @param type    解密类型
     */
    private void validateDecryptParams(String content, String key, String iv, CryptoType type) {
        if (content == null || content.trim().isEmpty()) {
            throw CryptoException.emptyData("解密", content);
        }
        if (key == null || key.trim().isEmpty()) {
            throw CryptoException.generalError("解密密钥不能为null或空", null, "解密", key);
        }
        if (type == null) {
            throw CryptoException.generalError("解密类型不能为null", null, "解密", type);
        }
        // RSA不需要IV，其他算法需要
        if (type != CryptoType.RSA && (iv == null || iv.trim().isEmpty())) {
            throw CryptoException.generalError("初始化向量不能为null或空", null, "解密", iv);
        }
    }


}
