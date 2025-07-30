package com.zsq.winter.encrypt.util;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.asymmetric.SignAlgorithm;
import cn.hutool.crypto.digest.DigestUtil;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.crypto.symmetric.DES;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import com.zsq.winter.encrypt.enums.CryptoType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * 加密解密工具类
 *
 * <p>提供多种加密解密算法的工具方法，包括：</p>
 * <ul>
 *   <li>凯撒密码加密解密</li>
 *   <li>AES加密解密</li>
 *   <li>DES加密解密</li>
 *   <li>MD5、SHA1等哈希算法</li>
 *   <li>RSA非对称加密解密（仅支持Base64格式密钥）</li>
 *   <li>数字签名</li>
 * </ul>
 *
 * <p>该类基于Hutool工具库实现，提供了简单易用的加密解密接口。</p>
 * <p><strong>注意：</strong>RSA加解密方法仅支持Base64格式的密钥，不支持PEM格式。</p>
 *
 * @author dadandiaoming
 * @since 1.0.0
 */
public class CryptoUtil {

    /**
     * 使用凯撒密码加密数据
     *
     * <p>凯撒密码是一种简单的替换加密算法，将明文中的每个字符按指定位移量进行偏移。</p>
     *
     * @param original 原文内容
     * @param key      位移量，正数向后偏移，负数向前偏移
     * @return 加密后的字符串
     * @throws IllegalArgumentException 如果original为null
     * @see #winterDecryptKaiser(String, int)
     */
    public static String winterEncryptKaiser(String original, int key) {
        // 将字符串转为字符数组
        char[] chars = original.toCharArray();
        StringBuilder sb = new StringBuilder();
        for (char aChar : chars) {
            // 获取字符的ascii编码
            int asciiCode = aChar;
            // 偏移数据
            asciiCode += key;
            // 将偏移后的数据转为字符
            char result = (char) asciiCode;
            // 拼接数据
            sb.append(result);
        }
        return sb.toString();
    }

    /**
     * 使用凯撒密码解密数据
     *
     * <p>将凯撒加密后的字符串还原为原文，位移量需与加密时一致。</p>
     *
     * @param encryptedData 密文内容
     * @param key           位移量，需与加密时一致
     * @return 解密后的原文
     * @throws IllegalArgumentException 如果encryptedData为null
     * @see #winterEncryptKaiser(String, int)
     */
    public static String winterDecryptKaiser(String encryptedData, int key) {
        // 将字符串转为字符数组
        char[] chars = encryptedData.toCharArray();
        StringBuilder sb = new StringBuilder();
        for (char aChar : chars) {
            // 获取字符的ASCII编码
            int asciiCode = aChar;
            // 偏移数据
            asciiCode -= key;
            // 将偏移后的数据转为字符
            char result = (char) asciiCode;
            // 拼接数据
            sb.append(result);
        }
        return sb.toString();
    }

    /**
     * 随机生成AES密钥
     *
     * <p>用于对称加密算法AES，返回16/24/32字节密钥。</p>
     *
     * @return AES密钥字节数组
     */
    public static byte[] winterGenerateKey() {
        return SecureUtil.generateKey(SymmetricAlgorithm.AES.getValue()).getEncoded();
    }

    /**
     * 使用AES算法加密数据，返回16进制字符串
     *
     * <p>默认模式为ECB/PKCS5Padding，适合一般用途。</p>
     *
     * @param key     AES密钥
     * @param content 待加密内容
     * @return 加密后的16进制字符串
     * @throws IllegalArgumentException 如果参数为null
     * @see #winterAesDecryptStr(byte[], String)
     */
    public static String winterAesEncryptHex(byte[] key, String content) {
        // 构建
        AES aes = SecureUtil.aes(key);
        // 加密为16进制表示
        return aes.encryptHex(content);
    }

    /**
     * 使用指定模式和填充方式的AES算法加密数据
     *
     * <p>支持CBC、CFB、OFB、CTR等模式，适合前后端对接。</p>
     *
     * @param mode    加密模式
     * @param padding 填充方式
     * @param key     AES密钥
     * @param iv      初始化向量
     * @param content 待加密内容
     * @return 加密后的16进制字符串
     * @throws IllegalArgumentException 如果参数为null
     * @see #winterAesDecryptStr(Mode, Padding, byte[], byte[], String)
     */
    public static String winterAesEncryptHex(Mode mode, Padding padding, byte[] key, byte[] iv, String content) {
        // 创建一个包含特定加密模式的列表
        ArrayList<Mode> list = CollUtil.toList(Mode.CBC, Mode.CFB, Mode.OFB, Mode.CTR);
        // 判断传入的模式是否在列表中
        if (list.contains(mode)) {
            // 如果在列表中，则使用该模式、填充方式、密钥和偏移量进行加密，并返回加密后的十六进制字符串
            return new AES(mode, padding, key, iv).encryptHex(content);
        } else {
            // 如果不在列表中，则使用该模式、填充方式和密钥进行加密（不使用偏移量），并返回加密后的十六进制字符串
            return new AES(mode, padding, key).encryptHex(content);
        }
    }

    /**
     * 使用AES算法解密16进制字符串
     *
     * <p>与winterAesEncryptHex配套使用，解密为原文。</p>
     *
     * @param key        AES密钥
     * @param encryptHex 加密后的16进制字符串
     * @return 解密后的原文
     * @throws IllegalArgumentException 如果参数为null
     * @throws RuntimeException         如果解密失败
     * @see #winterAesEncryptHex(byte[], String)
     */
    public static String winterAesDecryptStr(byte[] key, String encryptHex) {
        // 构建
        AES aes = SecureUtil.aes(key);
        // 解密
        return aes.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
    }

    /**
     * 使用指定模式和填充方式的AES算法解密数据
     *
     * <p>与winterAesEncryptHex(Mode, Padding, ...)配套使用。</p>
     *
     * @param mode    解密模式
     * @param padding 填充方式
     * @param key     AES密钥
     * @param iv      初始化向量
     * @param content 加密后的16进制字符串
     * @return 解密后的原文
     * @throws IllegalArgumentException 如果参数为null
     * @throws RuntimeException         如果解密失败
     * @see #winterAesEncryptHex(Mode, Padding, byte[], byte[], String)
     */
    public static String winterAesDecryptStr(Mode mode, Padding padding, byte[] key, byte[] iv, String content) {
        // 构建
        ArrayList<Mode> list = CollUtil.toList(Mode.CBC, Mode.CFB, Mode.OFB, Mode.CTR);
        if (list.contains(mode)) {
            return new AES(mode, padding, key, iv).decryptStr(content, CharsetUtil.CHARSET_UTF_8);
        } else {
            return new AES(mode, padding, key).decryptStr(content);
        }
    }

    /**
     * 使用DES算法加密数据，返回16进制字符串
     *
     * <p>默认模式为CBC/PKCS5Padding，适合一般用途。</p>
     *
     * @param key     DES密钥
     * @param content 待加密内容
     * @return 加密后的16进制字符串
     * @throws IllegalArgumentException 如果参数为null
     * @see #winterDesDecryptStr(byte[], String)
     */
    public static String winterDesEncryptHex(byte[] key, String content) {
        // 构建
        DES des = SecureUtil.des(key);
        // 加密为16进制表示
        return des.encryptHex(content);
    }

    /**
     * 使用指定模式和填充方式的DES算法加密数据
     *
     * <p>支持CBC、CFB、OFB、CTR等模式，适合前后端对接。</p>
     *
     * @param mode    加密模式
     * @param padding 填充方式
     * @param key     DES密钥
     * @param iv      初始化向量
     * @param content 待加密内容
     * @return 加密后的16进制字符串
     * @throws IllegalArgumentException 如果参数为null
     * @see #winterDesDecryptStr(Mode, Padding, byte[], byte[], String)
     */
    public static String winterDesEncryptHex(Mode mode, Padding padding, byte[] key, byte[] iv, String content) {
        // 加密为16进制表示
        ArrayList<Mode> list = CollUtil.toList(Mode.CBC, Mode.CFB, Mode.OFB, Mode.CTR);
        if (list.contains(mode)) {
            // 如果模式是CBC、CFB、OFB或CTR，则使用偏移量iv进行加密
            return new DES(mode, padding, key, iv).encryptHex(content);
        } else {
            // 否则，不使用偏移量iv进行加密
            return new DES(mode, padding, key).encryptHex(content);
        }
    }
    /**
     * 使用DES算法解密16进制字符串
     *
     * <p>与winterDesEncryptHex配套使用，解密为原文。</p>
     *
     * @param key        DES密钥
     * @param encryptHex 加密后的16进制字符串
     * @return 解密后的原文
     * @throws IllegalArgumentException 如果参数为null
     * @throws RuntimeException         如果解密失败
     * @see #winterDesEncryptHex(byte[], String)
     */
    public static String winterDesDecryptStr(byte[] key, String encryptHex) {
        // 构建DES实例，使用给定的密钥
        DES des = SecureUtil.des(key);
        // 使用DES实例解密加密后的十六进制字符串，并指定字符集为UTF-8
        return des.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
    }

    /**
     * 使用指定模式和填充方式的DES算法解密数据
     *
     * <p>与winterDesEncryptHex(Mode, Padding, ...)配套使用。</p>
     *
     * <p><strong>注意：</strong>当使用CBC、CFB、OFB或CTR模式时，需要提供初始化向量（iv）</p>
     *
     * @param mode    解密模式
     * @param padding 填充方式
     * @param key     DES密钥
     * @param iv      初始化向量
     * @param content 加密后的16进制字符串
     * @return 解密后的原文
     * @throws IllegalArgumentException 如果参数为null
     * @throws RuntimeException         如果解密失败
     * @see #winterDesEncryptHex(Mode, Padding, byte[], byte[], String)
     */
    public static String winterDesDecryptStr(Mode mode, Padding padding, byte[] key, byte[] iv, String content) {
        // 加密为16进制表示
        ArrayList<Mode> list = CollUtil.toList(Mode.CBC, Mode.CFB, Mode.OFB, Mode.CTR);
        // 根据模式是否需要初始化向量来选择合适的解密方式
        if (list.contains(mode)) {
            // 当模式为CBC、CFB、OFB或CTR时，使用初始化向量进行解密
            return new DES(mode, padding, key, iv).decryptStr(content, CharsetUtil.CHARSET_UTF_8);
        } else {
            // 其他模式不需要初始化向量进行解密
            return new DES(mode, padding, key).decryptStr(content);
        }
    }

    /**
     * 生成16位MD5哈希值
     *
     * <p>常用于文件校验、密码存储（需加盐）、数字签名等。</p>
     *
     * @param content 原文内容
     * @return 16位MD5哈希值
     */
    public static String winterMd5Hex16(String content) {
        return DigestUtil.md5Hex16(content);
    }

    /**
     * 生成SHA1哈希值
     *
     * <p>常用于数据完整性校验，比MD5更安全。</p>
     *
     * @param content 原文内容
     * @return SHA1哈希值
     */
    public static String winterSha1Hex(String content) {
        return DigestUtil.sha1Hex(content);
    }

    /**
     * 生成RSA公私钥对
     *
     * <p>适用于非对称加密、数字签名等场景。</p>
     * <p><strong>注意：</strong>生成的密钥为PKCS#8格式，兼容性更好。</p>
     *
     * @return Map，包含privateKey和publicKey（Base64格式）
     */
    public static Map<String, String> winterGenerateRsAKey() {
        try {
            // 使用Java原生的KeyPairGenerator生成RSA密钥对
            java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // 使用2048位密钥长度
            java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            // 获取私钥和公钥
            java.security.PrivateKey privateKey = keyPair.getPrivate();
            java.security.PublicKey publicKey = keyPair.getPublic();
            
            // 转换为Base64格式
            String privateKeyBase64 = java.util.Base64.getEncoder().encodeToString(privateKey.getEncoded());
            String publicKeyBase64 = java.util.Base64.getEncoder().encodeToString(publicKey.getEncoded());
            
            // 将私钥和公钥存入Map中
            Map<String, String> map = new HashMap<>();
            map.put("privateKey", privateKeyBase64);
            map.put("publicKey", publicKeyBase64);
            
            return map;
        } catch (Exception e) {
            throw new RuntimeException("生成RSA密钥对失败", e);
        }
    }

    /**
     * 使用公钥加密字符串，返回Base64密文
     *
     * @param content 明文内容
     * @param publicKeyBase64 公钥（Base64字符串，PKCS#8格式）
     * @return 加密后的Base64字符串
     */
    public static String rsaEncryptToBase64(String content, String publicKeyBase64) {
        try {
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            byte[] keyBytes = java.util.Base64.getDecoder().decode(publicKeyBase64);
            java.security.spec.X509EncodedKeySpec keySpec = new java.security.spec.X509EncodedKeySpec(keyBytes);
            java.security.PublicKey publicKey = keyFactory.generatePublic(keySpec);

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("RSA加密失败", e);
        }
    }

    /**
     * 使用私钥解密Base64密文，返回明文字符串
     *
     * @param base64Cipher Base64密文
     * @param privateKeyBase64 私钥（Base64字符串，PKCS#8格式）
     * @return 解密后的明文
     */
    public static String rsaDecryptFromBase64(String base64Cipher, String privateKeyBase64) {
        try {
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            byte[] keyBytes = java.util.Base64.getDecoder().decode(privateKeyBase64);
            java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(keyBytes);
            java.security.PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypted = cipher.doFinal(java.util.Base64.getDecoder().decode(base64Cipher));
            return new String(decrypted, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("RSA解密失败", e);
        }
    }
    /**
     * 使用RSA公钥加密数据
     *
     * <p>公钥加密，私钥解密，适合数据传输安全。</p>
     * <p><strong>注意：</strong>privateKey和publicKey必须是Base64格式的密钥。</p>
     *
     * @param privateKey 私钥（Base64格式）
     * @param publicKey  公钥（Base64格式）
     * @param content    明文内容
     * @return 加密后的字节数组
     */
    public static byte[] winterRsAPublicKeyEncrypt(String privateKey, String publicKey, String content) {
        // 创建RSA对象并初始化公钥和私钥。Hutool库的RSA类只支持Base64格式密钥。
        RSA rsa = new RSA(privateKey, publicKey);

        // 使用公钥对内容进行加密，并返回加密后的字节数组。加密过程确保只有持有对应私钥的接收方才能解密。
        return rsa.encrypt(content.getBytes(), KeyType.PublicKey);
    }

    /**
     * 使用RSA私钥加密数据
     *
     * <p>私钥加密，公钥解密，适合数字签名。</p>
     * <p><strong>注意：</strong>privateKey和publicKey必须是Base64格式的密钥。</p>
     *
     * @param privateKey 私钥（Base64格式）
     * @param publicKey  公钥（Base64格式）
     * @param content    明文内容
     * @return 加密后的字节数组
     */
    public static byte[] winterRsAPrivateKeyEncrypt(String privateKey, String publicKey, String content) {
        // 创建RSA对象并初始化公钥和私钥。Hutool库的RSA类只支持Base64格式密钥。
        RSA rsa = new RSA(privateKey, publicKey);

        // 使用私钥对内容进行加密，并返回加密后的字节数组。
        return rsa.encrypt(content.getBytes(), KeyType.PrivateKey);
    }

    /**
     * 使用RSA公钥加密数据，返回十六进制格式
     *
     * <p>公钥加密，私钥解密，适合数据传输安全。</p>
     * <p><strong>注意：</strong>privateKey和publicKey必须是Base64格式的密钥。</p>
     *
     * @param privateKey 私钥（Base64格式）
     * @param publicKey  公钥（Base64格式）
     * @param content    明文内容
     * @return 加密后的十六进制字符串
     */
    public static String winterRsAPublicKeyEncryptHex(String privateKey, String publicKey, String content) {
        // 创建RSA对象并初始化公钥和私钥。Hutool库的RSA类只支持Base64格式密钥。
        RSA rsa = new RSA(privateKey, publicKey);

        // 使用公钥对内容进行加密，并返回十六进制格式的加密字符串。
        return rsa.encryptHex(content.getBytes(), KeyType.PublicKey);
    }

    /**
     * 使用RSA私钥加密数据，返回十六进制格式
     *
     * <p>私钥加密，公钥解密，适合数字签名。</p>
     * <p><strong>注意：</strong>privateKey和publicKey必须是Base64格式的密钥。</p>
     *
     * @param privateKey 私钥（Base64格式）
     * @param publicKey  公钥（Base64格式）
     * @param content    明文内容
     * @return 加密后的十六进制字符串
     */
    public static String winterRsAPrivateKeyEncryptHex(String privateKey, String publicKey, String content) {
        // 创建RSA对象并初始化公钥和私钥。Hutool库的RSA类只支持Base64格式密钥。
        RSA rsa = new RSA(privateKey, publicKey);

        // 使用私钥对内容进行加密，并返回十六进制格式的加密字符串。
        return rsa.encryptHex(content.getBytes(), KeyType.PrivateKey);
    }

    /**
     * 使用RSA私钥解密公钥加密的数据
     *
     * <p>适合公钥加密、私钥解密的场景。</p>
     * <p><strong>注意：</strong>privateKey和publicKey必须是Base64格式的密钥。</p>
     *
     * @param privateKey 私钥（Base64格式）
     * @param publicKey  公钥（Base64格式）
     * @param encrypted  加密内容
     * @return 解密后的字节数组
     */
    public static byte[] winterRsAPrivateKeyDecrypt(String privateKey, String publicKey, String encrypted) {
        // 初始化RSA加密器，同时加载私钥和公钥。Hutool库的RSA类只支持Base64格式密钥。
        RSA rsa = new RSA(privateKey, publicKey);
        // 使用私钥对加密数据进行解密操作。
        return rsa.decrypt(encrypted, KeyType.PrivateKey);
    }

    /**
     * 使用RSA公钥解密私钥加密的数据
     *
     * <p>适合私钥加密、公钥解密的场景。</p>
     * <p><strong>注意：</strong>privateKey和publicKey必须是Base64格式的密钥。</p>
     *
     * @param privateKey 私钥（Base64格式）
     * @param publicKey  公钥（Base64格式）
     * @param encrypted  加密内容
     * @return 解密后的字节数组
     */
    public static byte[] winterRsAPublicKeyDecrypt(String privateKey, String publicKey, String encrypted) {
        // 初始化RSA加密器，同时加载私钥和公钥。Hutool库的RSA类只支持Base64格式密钥。
        RSA rsa = new RSA(privateKey, publicKey);
        // 使用公钥对加密数据进行解密操作。
        return rsa.decrypt(encrypted, KeyType.PublicKey);
    }

    /**
     * 使用RSA私钥解密十六进制格式的数据
     *
     * <p>适合公钥加密、私钥解密的场景。</p>
     * <p><strong>注意：</strong>privateKey和publicKey必须是Base64格式的密钥。</p>
     *
     * @param privateKey 私钥（Base64格式）
     * @param publicKey  公钥（Base64格式）
     * @param encrypted  十六进制格式的加密内容
     * @return 解密后的字符串
     */
    public static String winterRsAPrivateKeyDecryptHex(String privateKey, String publicKey, String encrypted) {
        // 初始化RSA加密器，同时加载私钥和公钥。Hutool库的RSA类只支持Base64格式密钥。
        RSA rsa = new RSA(privateKey, publicKey);
        // 使用私钥对十六进制加密数据进行解密操作。
        return rsa.decryptStr(encrypted, KeyType.PrivateKey);
    }

    /**
     * 使用RSA公钥解密十六进制格式的数据
     *
     * <p>适合私钥加密、公钥解密的场景。</p>
     * <p><strong>注意：</strong>privateKey和publicKey必须是Base64格式的密钥。</p>
     *
     * @param privateKey 私钥（Base64格式）
     * @param publicKey  公钥（Base64格式）
     * @param encrypted  十六进制格式的加密内容
     * @return 解密后的字符串
     */
    public static String winterRsAPublicKeyDecryptHex(String privateKey, String publicKey, String encrypted) {
        // 初始化RSA加密器，同时加载私钥和公钥。Hutool库的RSA类只支持Base64格式密钥。
        RSA rsa = new RSA(privateKey, publicKey);
        // 使用公钥对十六进制加密数据进行解密操作。
        return rsa.decryptStr(encrypted, KeyType.PublicKey);
    }

    /**
     * 使用MD5withRSA算法进行数字签名
     *
     * <p>常用于身份认证、数据完整性校验。</p>
     * <p><strong>注意：</strong>privateKey和publicKey必须是Base64格式的密钥。</p>
     *
     * @param privateKey 私钥（Base64格式）
     * @param publicKey  公钥（Base64格式）
     * @param content    原文内容
     * @return 数字签名字节数组
     */
    public static byte[] winterMd5withRsaSign(String privateKey, String publicKey, String content) {
        // 使用Base64格式的私钥、公钥进行MD5withRSA签名，Hutool库只支持Base64格式密钥
        return SecureUtil.sign(SignAlgorithm.MD5withRSA, privateKey, publicKey).sign(content.getBytes());
    }

    /**
     * 验证MD5withRSA数字签名
     *
     * <p>常用于身份认证、数据完整性校验。</p>
     * <p><strong>注意：</strong>privateKey和publicKey必须是Base64格式的密钥。</p>
     *
     * @param privateKey 私钥（Base64格式）
     * @param publicKey  公钥（Base64格式）
     * @param signData   签名数据
     * @param content    原文内容
     * @return 验证通过返回true，否则false
     */
    public static boolean winterMd5withRsaVerify(String privateKey, String publicKey, byte[] signData, String content) {
        // 使用Base64格式的私钥、公钥进行MD5withRSA签名验证，Hutool库只支持Base64格式密钥
        return SecureUtil.sign(SignAlgorithm.MD5withRSA, privateKey, publicKey).verify(content.getBytes(), signData);
    }
}