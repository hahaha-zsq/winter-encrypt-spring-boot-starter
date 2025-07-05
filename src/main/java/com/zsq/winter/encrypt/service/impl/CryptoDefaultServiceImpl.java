package com.zsq.winter.encrypt.service.impl;

import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import com.zsq.winter.encrypt.enums.CryptoType;
import com.zsq.winter.encrypt.service.CryptoService;
import com.zsq.winter.encrypt.util.CryptoUtil;

import java.nio.charset.StandardCharsets;

/**
 * 实现了CryptoService接口的默认加密解密服务类
 * 提供了DES和AES加密解密的具体实现
 */
public class CryptoDefaultServiceImpl implements CryptoService {

    /**
     * 根据指定的加密类型、模式、填充方式、密钥和偏移量加密内容
     *
     * @param mode 加密使用的模式，例如ECB、CBC等
     * @param padding 加密使用的填充方式，例如PKCS5Padding、NoPadding等
     * @param content 待加密的内容
     * @param key 加密使用的密钥
     * @param iv 加密使用的偏移量
     * @param type 加密类型，决定使用DES还是AES加密
     * @return 加密后的字符串
     */
    @Override
    public String encrypt(Mode mode, Padding padding, String content, String key, String iv, CryptoType type) {
        String str = "";
        // 根据加密类型调用相应的加密方法
        switch (type) {
            case DES:
                // 使用DES算法进行加密
                str = CryptoUtil.winterDesEncryptHex(mode, padding, key.getBytes(StandardCharsets.UTF_8), iv.getBytes(StandardCharsets.UTF_8), content);
                break;
            default:
                // 默认使用AES算法进行加密
                str = CryptoUtil.winterAesEncryptHex(mode, padding, key.getBytes(StandardCharsets.UTF_8), iv.getBytes(StandardCharsets.UTF_8), content);
        }
        return str;
    }

    /**
     * 根据指定的解密类型、模式、填充方式、密钥和偏移量解密内容
     *
     * @param mode 解密使用的模式，例如ECB、CBC等
     * @param padding 解密使用的填充方式，例如PKCS5Padding、NoPadding等
     * @param content 待解密的内容
     * @param key 解密使用的密钥
     * @param iv 解密使用的偏移量
     * @param type 解密类型，决定使用DES还是AES解密
     * @return 解密后的字符串
     */
    @Override
    public String decrypt(Mode mode, Padding padding, String content, String key, String iv, CryptoType type) {
        String str = "";
        // 根据解密类型调用相应的解密方法
        switch (type) {
            case DES:
                // 使用DES算法进行解密
                str = CryptoUtil.winterDesDecryptStr(mode, padding, key.getBytes(StandardCharsets.UTF_8), iv.getBytes(StandardCharsets.UTF_8), content);
                break;
            default:
                // 默认使用AES算法进行解密
                str = CryptoUtil.winterAesDecryptStr(mode, padding, key.getBytes(StandardCharsets.UTF_8), iv.getBytes(StandardCharsets.UTF_8), content);
        }
        return str;
    }
}
