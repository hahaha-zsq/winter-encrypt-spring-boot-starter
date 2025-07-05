# ❄️ winter-encrypt-spring-boot-starter

> 一个开箱即用的 Spring Boot 加解密工具包，内置常用对称/非对称加密算法，支持注解式加解密，助力数据安全！

---

## ✨ 特性亮点

- 🚀 **零配置自动装配**，即插即用
- 🔒 支持 **AES/DES** 等主流加密算法
- 🏷️ 注解驱动，**@Encrypt/@Decrypt/@FieldEncrypt** 一键加解密（解密目前没写，一般情况下请求参数会进行spring-boot-starter-validation进行参数的校验，意味着前端不需要加密，真需要的话，请使用内置的工具类收到解密）
- 🛡️ 支持字段级加密，灵活可扩展
- 📦 兼容 Spring Boot 2.x
- 📄 丰富的配置项，支持自定义实现

---

## 📦 快速开始

### 1. 引入依赖

```xml
<dependency>
    <groupId>io.github.hahaha-zsq</groupId>
    <artifactId>winter-encrypt-spring-boot-starter</artifactId>
    <version>0.0.1</version>
</dependency>
```

### 2. 配置 application.yml

```yaml
winter-crypto:
  encrypt-key: "your-encrypt-key"   # 加密密钥
  decrypt-key: "your-decrypt-key"   # 解密密钥
  iv: "your-iv"                     # 偏移量（如CBC模式必填）
  is-print: true                     # 是否打印banner（可选）
```

---

## ⚙️ 配置项说明

| 配置项                  | 说明           | 是否必填 | 默认值   |
|------------------------|----------------|---------|---------|
| winter-crypto.encrypt-key | 加密密钥       | 是      | -       |
| winter-crypto.decrypt-key | 解密密钥       | 是      | -       |
| winter-crypto.iv          | 偏移量         | 是      | -       |
| winter-crypto.is-print    | 是否打印banner | 否      | true    |

---

## 🏷️ 注解说明

- `@Encrypt`：用于方法上，返回对象字段自动加密
- `@Decrypt`：用于方法上，参数自动解密（如有实现）
- `@FieldEncrypt`：用于类字段上，指定字段加密算法/模式/填充方式

> **注：** `@Encrypt` 与 `@FieldEncrypt` 配合使用，`@Encrypt` 触发加密流程，`@FieldEncrypt` 精确指定加密字段和策略。

---

## 🚦 典型用法示例

### 1. DTO 示例
```java
@Data
public class Result<T> {

    //状态码
    private Integer code;
    //信息
    private String message;
    //数据
    @FieldEncrypt(mode= Mode.CBC)
    private T data;

    //构造私有化
    private Result() {
    }

    //设置数据,返回对象的方法
    public static <T> Result<T> build(T data, Integer code, String message) {
        //创建Result对象，设置值，返回对象
        Result<T> result = new Result<>();
        //判断返回结果中是否需要数据
        if (ObjectUtil.isNotEmpty(data)) {
            //设置数据到result对象
            result.setData(data);
        }
        //设置其他值
        result.setCode(code);
        result.setMessage(message);
        //返回设置值之后的对象
        return result;
    }

    //设置数据,返回对象的方法
    public static <T> Result<T> build(T data, ResultCodeEnum resultCodeEnum) {
        //创建Result对象，设置值，返回对象
        Result<T> result = new Result<>();
        //判断返回结果中是否需要数据
        if (!ObjectUtils.isEmpty(data)) {
            //设置数据到result对象
            result.setData(data);
        }
        //设置其他值
        result.setCode(resultCodeEnum.getCode());
        result.setMessage(resultCodeEnum.getMessage());
        //返回设置值之后的对象
        return result;
    }

    //成功的方法
    public static <T> Result<T> ok(T data) {
        return build(data, ResultCodeEnum.SUCCESS.getCode(),I18nUtil.get(ResultCodeEnum.SUCCESS.getMessage()));
    }

    //失败的方法
    public static <T> Result<T> fail(T data) {
        return build(data, ResultCodeEnum.FAIL.getCode(),I18nUtil.get(ResultCodeEnum.FAIL.getMessage()));
    }

    public static <T> Result<T> fail(T data, ResultCodeEnum resultCodeEnum) {
        return build(data, resultCodeEnum);
    }

    public static <T> Result<T> fail(Integer code, String message) {
        //创建Result对象，设置值，返回对象
        Result<T> result = new Result<>();
        //设置其他值
        result.setCode(code);
        result.setMessage(message);
        return result;
    }
}
```

### 2. Controller 示例
```java
@Encrypt
@PostMapping("/getPagingRoleInfoByConditions")
public Result<?> getPagingRoleInfoByConditions(@RequestBody @Validated({SysRoleDTO.Query.class}) SysRoleDTO roleDto) {
    return sysRoleService.getPagingRoleInfoByConditions(roleDto);
}
```

### 3. 配置文件示例
```yaml
winter-crypto:
  decrypt-key: 346a3f9f4c1988cb7a507cc177923ac7
  encrypt-key: 346a3f9f4c1988cb7a507cc177923ac7
  iv: 1234567887654321
```

![img.png](img.png)

---

## 🛠️ 进阶用法

### 自定义加密实现
只需实现 `CryptoService` 接口，并注入为 Spring Bean，即可覆盖默认加解密逻辑。

```java
import com.zsq.winter.encrypt.service.CryptoService;
// ... 实现 encrypt/decrypt 方法 ...
```

---

## 🧰 常用工具类方法说明

`CryptoUtil` 工具类内置了多种加解密、摘要、密钥生成等静态方法，便于开发者灵活调用。

| 方法名 | 说明 | 示例 |
|--------|------|------|
| `winterAesEncryptHex` | AES加密（支持多种模式/填充） | `CryptoUtil.winterAesEncryptHex(mode, padding, key, iv, content)` |
| `winterAesDecryptStr` | AES解密 | `CryptoUtil.winterAesDecryptStr(mode, padding, key, iv, content)` |
| `winterDesEncryptHex` | DES加密 | `CryptoUtil.winterDesEncryptHex(mode, padding, key, iv, content)` |
| `winterDesDecryptStr` | DES解密 | `CryptoUtil.winterDesDecryptStr(mode, padding, key, iv, content)` |
| `winterMd5Hex16` | 16位MD5摘要 | `CryptoUtil.winterMd5Hex16(content)` |
| `winterSha1Hex` | SHA1摘要 | `CryptoUtil.winterSha1Hex(content)` |
| `winterGenerateKey` | 随机生成AES密钥 | `CryptoUtil.winterGenerateKey()` |
| `winterGenerateRsAKey` | 生成RSA公私钥对 | `CryptoUtil.winterGenerateRsAKey()` |
| `winterRsAPublicKeyEncrypt` | RSA公钥加密 | `CryptoUtil.winterRsAPublicKeyEncrypt(privateKey, publicKey, content)` |
| `winterRsAPrivateKeyEncrypt` | RSA私钥加密 | `CryptoUtil.winterRsAPrivateKeyEncrypt(privateKey, publicKey, content)` |
| `winterRsAPrivateKeyDecrypt` | RSA私钥解密 | `CryptoUtil.winterRsAPrivateKeyDecrypt(privateKey, publicKey, encrypted)` |
| `winterRsAPublicKeyDecrypt` | RSA公钥解密 | `CryptoUtil.winterRsAPublicKeyDecrypt(privateKey, publicKey, encrypted)` |
| `winterMd5withRsaSign` | MD5withRSA数字签名 | `CryptoUtil.winterMd5withRsaSign(privateKey, publicKey, content)` |
| `winterMd5withRsaVerify` | 验证MD5withRSA签名 | `CryptoUtil.winterMd5withRsaVerify(privateKey, publicKey, signData, content)` |

#### 示例：AES加密解密
```java
byte[] key = CryptoUtil.winterGenerateKey();
String iv = "abcdef1234567890";
String content = "hello world";
String encrypted = CryptoUtil.winterAesEncryptHex(Mode.CBC, Padding.PKCS5Padding, key, iv.getBytes(), content);
String decrypted = CryptoUtil.winterAesDecryptStr(Mode.CBC, Padding.PKCS5Padding, key, iv.getBytes(), encrypted);
```

#### 示例：生成RSA密钥对
```java
Map<String, String> keyMap = CryptoUtil.winterGenerateRsAKey();
String privateKey = keyMap.get("privateKey");
String publicKey = keyMap.get("publicKey");
```

---

## ❓ 常见问题 FAQ

### @Encrypt 和 @FieldEncrypt 有什么联系？

| 注解         | 作用范围   | 主要功能                         | 典型用法 |
|--------------|------------|----------------------------------|----------|
| `@Encrypt`   | 方法级别   | 触发加密流程，拦截返回对象        | Controller方法 |
| `@FieldEncrypt` | 字段级别 | 指定字段加密及加密策略            | DTO/VO字段 |

- `@Encrypt` 用于方法上，AOP切面拦截后会遍历返回对象的所有字段。
- 只有被 `@FieldEncrypt` 标记的字段才会被加密，未标记字段保持原样。
- `@FieldEncrypt` 可自定义加密类型、模式、填充方式，实现细粒度加密控制。

**示例流程：**
1. Controller方法加 `@Encrypt`，返回对象中有 `@FieldEncrypt` 字段。
2. 返回时自动对这些字段加密，其他字段不变。

---

### 其他常见问题

- **Q: 启动报缺少密钥/iv？**
  - A: 请检查 `application.yml` 配置项是否齐全。
- **Q: 如何自定义加密算法？**
  - A: 实现 `CryptoService` 并注入Spring容器即可。
- **Q: 支持哪些加密模式/填充？**
  - A: 支持 Hutool 的所有 `Mode` 和 `Padding` 枚举。

---

## 🔗 相关链接

- [GitHub 仓库](https://github.com/hahaha-zsq/winter-encrypt-spring-boot-starter)
- [Hutool 文档](https://hutool.cn/docs/#/crypto/)
- [Spring Boot 官方文档](https://spring.io/projects/spring-boot)

---

> ❤️ 欢迎 Star & PR，更多特性敬请期待！
