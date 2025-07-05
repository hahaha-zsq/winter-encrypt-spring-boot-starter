package com.zsq.winter.encrypt.service;

import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import com.zsq.winter.encrypt.enums.CryptoType;


/**
 * 加密解密服务接口
 * 定义了加密和解密数据的方法，支持不同的加密模式、填充方式、加密密钥和初始化向量
 */
public interface CryptoService {

    /**
     * 加密数据的方法
     *
     * @param mode 加密模式，决定了使用何种加密算法模式（例如CBC、ECB等）
     * @param padding 填充方式，用于处理数据块的填充（例如PKCS5Padding、NoPadding等）
     * @param content 待加密的内容，即原始数据
     * @param key 加密密钥，用于加密数据的关键信息
     * @param iv 初始化向量，某些加密模式（如CBC）需要的额外参数
     * @param type 加密类型，指加密算法的类型（例如AES、DES等）
     * @return 返回加密后的数据，通常为密文的字符串表示
     */
    String encrypt(Mode mode, Padding padding, String content, String key, String iv, CryptoType type);

    /**
     * 解密数据的方法
     *
     * @param mode 解密模式，需要与加密时使用的模式相对应
     * @param padding 填充方式，需要与加密时使用的填充方式相匹配
     * @param content 待解密的内容，即加密后的数据
     * @param key 解密密钥，需要与加密密钥相匹配
     * @param iv 初始化向量，如果加密模式需要，必须与加密时使用的一致
     * @param type 解密类型，需要与加密时使用的加密算法类型一致
     * @return 返回解密后的数据，即原始信息的字符串表示
     */
    String decrypt(Mode mode, Padding padding, String content, String key, String iv, CryptoType type);
}
