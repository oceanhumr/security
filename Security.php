<?php
// +----------------------------------------------------------------------
// | LIKE [ JUST DO IT ]
// +----------------------------------------------------------------------
// | Author: Mr.hu <huhaiyang7788@163.com>
// +----------------------------------------------------------------------
// | DESC: 密码术
// +----------------------------------------------------------------------
// | Date Time: 2018/3/5 17:49
// +----------------------------------------------------------------------


namespace su\security;


use su\security\tools\StringHelper;

class Security
{


    /**
     * @var 将用于加密和解密的密码字符串
     */
    public $cipher = 'AES-128-CBC';
    /**
     * @var array[] 每个支持OpenSSL密码的块大小和密钥大小的查找表。
     *
     *  在每个元素中，密钥是OpenSSL支持的密码之一(@请参见OpenSSL_get_ciPHERS())。
     *  该值是一个由两个整数组成的数组，第一个是密码的块大小(以字节为单位)，第二个是
     *  键大小(以字节为单位)。
     *
     *>警告：我们推荐的所有OpenSSL密码都在默认值中，即在CBC模式下的AES。
     */
    public $allowedCiphers = [
        'AES-128-CBC' => [16, 16],
        'AES-192-CBC' => [16, 24],
        'AES-256-CBC' => [16, 32],
    ];
    /**
     * @var string 用于密钥推导的哈希算法。推荐Sha 256、Sha 384或Sha 512。
     * @see [hash_algos()](http://php.net/manual/en/function.hash-algos.php)
     */
    public $kdfHash = 'sha256';
    /**
     * @var string 消息认证的哈希算法。推荐SHA256，SHA384或SHA512。
     * @see [hash_algos()](http://php.net/manual/en/function.hash-algos.php)
     */
    public $macHash = 'sha256';
    /**
     * @var string 用于派生消息身份验证密钥的HKDF信息值。
     * @see hkdf()
     */
    public $authKeyInfo = 'AuthorizationKey';
    /**
     * @var int 派生迭代数。
     * 设置尽可能高，以阻止字典密码攻击。
     */
    public $derivationIterations = 100000;
    /**
     * @var string 策略，该策略应用于生成密码哈希
     * 现有战略：
     *-‘Password_Hash’--使用PHP‘Password_Hash()’函数和密码_DEFAULT算法。
     *建议使用此选项，但需要PHP版本>=5.5.0
     *-‘crypt’--使用PHP`crypt()‘函数。
     *@自2.0.7版本以来被弃用，[[generatePasswordHash()]]忽略[[passwordHashStrategy]]和
     *在可用时使用“Password_Hash()”，在没有密码时使用“crypt()”.
     */
    public $passwordHashStrategy;
    /**
     * @var int 密码哈希使用的默认成本。
     * 允许的值在4到31之间。
     */
    public $passwordHashCost = 13;


    /**
     * 使用密码加密数据。
     *使用PBKDF 2和随机盐从密码中派生用于加密和身份验证的密钥，
     *这是故意缓慢地防止字典攻击。使用[[EncryptByKey()]]
     *使用加密密钥而不是密码快速加密。密钥推导时间为
     *由[[$派生项]确定，应尽可能高。
     *加密数据包括密钥消息认证代码(Mac)，因此不需要
     *散列输入或输出数据。
     *>注意：尽可能避免使用密码加密。没有什么能防止
     *质量差或密码受损。
     *@param string $data 要加密的数据
     *@param string $password 密码用于加密
     *@返回加密数据字符串
     *@请参见解密ByPassword()
     *@见EncryptByKey()
     */

    public function encryptByPassword($data, $password)
    {
        return $this->encrypt($data, true, $password, null);
    }

    /**
     * 使用加密密钥加密数据。
     *使用香港发展基金及随机盐从输入密钥衍生加密及认证密钥，
     *相对于[[EncryptByPassword()]]来说，速度非常快。输入键必须正确。
     *随机使用[[generateRandomKey()]]生成密钥。
     *加密数据包括密钥消息认证代码(Mac)，因此不需要
     *散列输入或输出数据。
     *@param string $data 要加密的数据
     *@param string $inputKey用于加密和身份验证的输入
     *@param string$info可选上下文和应用程序特定信息，请参阅[[hkdf()]]
     *@返回加密数据字符串
     *@请参见解密ByKey()
     *@见EncryptByPassword()
     */
    public function encryptByKey($data, $inputKey, $info = null)
    {
        return $this->encrypt($data, false, $inputKey, $info);
    }

    /**
     * 验证和解密使用[[EncryptByPassword()]]加密的数据。
     *@param string $data 加密数据解密
     *@param string $password 用于解密的密码
     *@在身份验证失败时返回解密数据或false的bool字符串
     *@见EncryptByPassword()
     */
    public function decryptByPassword($data, $password)
    {
        return $this->decrypt($data, true, $password, null);
    }

    /**
     * 验证和解密使用[[EncryptByKey()]]加密的数据。
     *@param string $data 加密数据解密
     *@param string $inputKey 用于加密和身份验证的输入
     *@param string $info可选上下文和应用程序特定信息，请参阅[[hkdf()]]
     *@在身份验证失败时返回解密数据或false的bool字符串
     *@见EncryptByKey()
     */
    public function decryptByKey($data, $inputKey, $info = null)
    {
        return $this->decrypt($data, false, $inputKey, $info);
    }

    /**
     * 加密数据。
     *@param string $data 将被加密
     *@param bool $passwordbasedset true使用基于密码的密钥派生
     *@param string $secret 加密密码或密钥
     *@param string NULL $info上下文/应用程序特定信息，例如用户ID
     *@返回加密数据字符串
     *@抛出OpenSSL上未加载的InvalidConfigException
     *@对OpenSSL错误抛出异常
     *@请参阅解密()
     */
    protected function encrypt($data, $passwordBased, $secret, $info)
    {
        if (!extension_loaded('openssl')) {
            throw new \Exception('Encryption requires the OpenSSL PHP extension');
        }
        if (!isset($this->allowedCiphers[$this->cipher][0], $this->allowedCiphers[$this->cipher][1])) {
            throw new \Exception($this->cipher . ' is not an allowed cipher');
        }

        list($blockSize, $keySize) = $this->allowedCiphers[$this->cipher];

        $keySalt = $this->generateRandomKey($keySize);
        if ($passwordBased) {
            $key = $this->pbkdf2($this->kdfHash, $secret, $keySalt, $this->derivationIterations, $keySize);
        } else {
            $key = $this->hkdf($this->kdfHash, $secret, $keySalt, $info, $keySize);
        }

        $iv = $this->generateRandomKey($blockSize);

        $encrypted = openssl_encrypt($data, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            throw new \Exception('OpenSSL failure on encryption: ' . openssl_error_string());
        }

        $authKey = $this->hkdf($this->kdfHash, $key, null, $this->authKeyInfo, $keySize);
        $hashed = $this->hashData($iv . $encrypted, $authKey);

        /*
         * 输出：[keysalt][mac][iv][密文]
         * 键盐是键大小字节长的
         *-mac：消息验证代码，长度与mac_hash输出相同
         *-IV：初始化向量，长度$Blocksize
         */
        return $keySalt . $hashed;
    }

    /**
     * 解密数据。
     *
     *@param string $data 加密数据将被解密。
     *@param bool $passwordbasedset true使用基于密码的密钥派生
     *@param string $secret 解密密码或密钥
     *@param string NULL$info上下文/应用程序特定信息，@请参见Encrypt()
     *
     *@在身份验证失败时返回解密数据或false的bool字符串
     *@抛出OpenSSL上未加载的InvalidConfigException
     *@对OpenSSL错误抛出异常
     *@见Encrypt()
     */
    protected function decrypt($data, $passwordBased, $secret, $info)
    {
        if (!extension_loaded('openssl')) {
            throw new \Exception('Encryption requires the OpenSSL PHP extension');
        }
        if (!isset($this->allowedCiphers[$this->cipher][0], $this->allowedCiphers[$this->cipher][1])) {
            throw new \Exception($this->cipher . ' is not an allowed cipher');
        }

        list($blockSize, $keySize) = $this->allowedCiphers[$this->cipher];

        $keySalt = StringHelper::byteSubstr($data, 0, $keySize);
        if ($passwordBased) {
            $key = $this->pbkdf2($this->kdfHash, $secret, $keySalt, $this->derivationIterations, $keySize);
        } else {
            $key = $this->hkdf($this->kdfHash, $secret, $keySalt, $info, $keySize);
        }

        $authKey = $this->hkdf($this->kdfHash, $key, null, $this->authKeyInfo, $keySize);
        $data = $this->validateData(StringHelper::byteSubstr($data, $keySize, null), $authKey);
        if ($data === false) {
            return false;
        }

        $iv = StringHelper::byteSubstr($data, 0, $blockSize);
        $encrypted = StringHelper::byteSubstr($data, $blockSize, null);

        $decrypted = openssl_decrypt($encrypted, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            throw new \Exception('OpenSSL failure on decryption: ' . openssl_error_string());
        }

        return $decrypted;
    }

    /**
     * 使用标准的HKDF算法从给定的输入键中派生密钥。
     *实施[rfc 5869](https：//tools.ietf.org/html/rfc 5869)中指定的HKDF。
     *推荐使用SHA-2散列算法之一：Sha 224、Sha 256、Sha 384或Sha 512。
     *@param string $algo‘散列算法由`散列_hmac()’支持，例如。“沙-256”
     *@param string $inputKey
     *@param string $salt随机盐
     *@param string$info可选信息将派生的关键材料绑定到应用程序-
     *和特定于上下文的信息，例如用户ID或api版本，请参见
     *[RFC 5869](https：//tools.ietf.org/html/rfc 5869)
     *@param int$length输出键的长度(以字节为单位)。如果为0，则输出键为
     *哈希算法输出的长度。
     *@会在HMAC生成失败时抛出InvalidParamException。
     *@返回派生键字符串
     */
    public function hkdf($algo, $inputKey, $salt = null, $info = null, $length = 0)
    {
        if (function_exists('hash_hkdf')) {
            $outputKey = hash_hkdf($algo, $inputKey, $length, $info, $salt);
            if ($outputKey === false) {
                throw new \Exception('Invalid parameters to hash_hkdf()');
            }

            return $outputKey;
        }

        $test = @hash_hmac($algo, '', '', true);
        if (!$test) {
            throw new \Exception('Failed to generate HMAC with hash algorithm: ' . $algo);
        }
        $hashLength = StringHelper::byteLength($test);
        if (is_string($length) && preg_match('{^\d{1,16}$}', $length)) {
            $length = (int) $length;
        }
        if (!is_int($length) || $length < 0 || $length > 255 * $hashLength) {
            throw new \Exception('Invalid length');
        }
        $blocks = $length !== 0 ? ceil($length / $hashLength) : 1;

        if ($salt === null) {
            $salt = str_repeat("\0", $hashLength);
        }
        $prKey = hash_hmac($algo, $inputKey, $salt, true);

        $hmac = '';
        $outputKey = '';
        for ($i = 1; $i <= $blocks; $i++) {
            $hmac = hash_hmac($algo, $hmac . $info . chr($i), $prKey, true);
            $outputKey .= $hmac;
        }

        if ($length !== 0) {
            $outputKey = StringHelper::byteSubstr($outputKey, 0, $length);
        }

        return $outputKey;
    }

    /**
     * 使用标准的PBKDF 2算法从给定的密码中派生密钥。
     *推荐使用SHA-2散列算法之一：Sha 224、Sha 256、Sha 384或Sha 512。
     *@param string $algo‘散列算法由`散列_hmac()’支持，例如。“沙-256”
     *@param string $password 源密码
     *@param string $salt随机盐
     *@param int$iterations散列算法的迭代次数。定得很高
     *有可能阻止字典密码攻击。
     *@param int$length输出键的长度(以字节为单位)。如果为0，则输出键为
     *哈希算法输出的长度。
     *@返回派生键字符串
     *@引发InvalidParamException，当哈希生成由于给定的无效参数而失败时抛出。
     */
    public function pbkdf2($algo, $password, $salt, $iterations, $length = 0)
    {
        if (function_exists('hash_pbkdf2')) {
            $outputKey = hash_pbkdf2($algo, $password, $salt, $iterations, $length, true);
            if ($outputKey === false) {
                throw new \Exception('Invalid parameters to hash_pbkdf2()');
            }

            return $outputKey;
        }

        $test = @hash_hmac($algo, '', '', true);
        if (!$test) {
            throw new \Exception('Failed to generate HMAC with hash algorithm: ' . $algo);
        }
        if (is_string($iterations) && preg_match('{^\d{1,16}$}', $iterations)) {
            $iterations = (int) $iterations;
        }
        if (!is_int($iterations) || $iterations < 1) {
            throw new \Exception('Invalid iterations');
        }
        if (is_string($length) && preg_match('{^\d{1,16}$}', $length)) {
            $length = (int) $length;
        }
        if (!is_int($length) || $length < 0) {
            throw new \Exception('Invalid length');
        }
        $hashLength = StringHelper::byteLength($test);
        $blocks = $length !== 0 ? ceil($length / $hashLength) : 1;

        $outputKey = '';
        for ($j = 1; $j <= $blocks; $j++) {
            $hmac = hash_hmac($algo, $salt . pack('N', $j), $password, true);
            $xorsum = $hmac;
            for ($i = 1; $i < $iterations; $i++) {
                $hmac = hash_hmac($algo, $hmac, $password, true);
                $xorsum ^= $hmac;
            }
            $outputKey .= $xorsum;
        }

        if ($length !== 0) {
            $outputKey = StringHelper::byteSubstr($outputKey, 0, $length);
        }

        return $outputKey;
    }

    /**
     * 用键控哈希值对数据进行前缀，以便在数据被篡改时能够检测到。
     *不需要散列[[cryptByKey()]]或[[EncryptByPassword()]]的输入或输出
     *当这些方法执行任务时。
     *@param string $data数据要保护的数据
     *@param string $key用于生成散列的秘密密钥。应该是安全的
     *密码钥匙。
     *@param bool$rawHash生成的散列值是否为原始二进制格式。如果是假的，小写
     *生成十六进制数字。
     *@返回以键控哈希作为前缀的数据字符串
     *@在HMAC生成失败时抛出InvalidConfigException。
     *@请参见valdateData()
     *@见generateRandomKey()
     *@见hkdf()
     *@见pbkdf 2()
     */
    public function hashData($data, $key, $rawHash = false)
    {
        $hash = hash_hmac($this->macHash, $data, $key, $rawHash);
        if (!$hash) {
            throw new \Exception('Failed to generate HMAC with hash algorithm: ' . $this->macHash);
        }

        return $hash . $data;
    }

    /**
     * 验证给定数据是否被篡改。
     *@param string$data将验证的数据。数据必须是以前的
     *由[[hashData()]]生成。
     *@param string $key以前用于为[[hashData()]]中的数据生成散列的秘密密钥。
     *函数查看系统上支持的哈希算法。这一定是一样的
     *在为数据生成哈希时传递给[[hashData()]]的值。
     *@param bool$rawHash--这应该与使用[[hashData()]]生成数据时的值相同。
     *它指示数据中的哈希值是否为二进制格式。如果为false，则表示散列值包含
     *只有小写十六进制数字。
     *生成十六进制数字。
     *@返回字符串为false，去掉散列后的真实数据。如果数据被篡改，则为false。
     *@在HMAC生成失败时抛出InvalidConfigException。
     *@见hashData()
     */
    public function validateData($data, $key, $rawHash = false)
    {
        $test = @hash_hmac($this->macHash, '', '', $rawHash);
        if (!$test) {
            throw new \Exception('Failed to generate HMAC with hash algorithm: ' . $this->macHash);
        }
        $hashLength = StringHelper::byteLength($test);
        if (StringHelper::byteLength($data) >= $hashLength) {
            $hash = StringHelper::byteSubstr($data, 0, $hashLength);
            $pureData = StringHelper::byteSubstr($data, $hashLength, null);

            $calculatedHash = hash_hmac($this->macHash, $pureData, $key, $rawHash);

            if ($this->compareString($hash, $calculatedHash)) {
                return $pureData;
            }
        }

        return false;
    }

    private $_useLibreSSL;
    private $_randomFile;

    /**
     * 生成指定数目的随机字节。
     *注意，产出可能不是ASCII。
     *@如果需要字符串，请参见generateRandomString()。
     *@param int$ength要生成的字节数
     *@返回字符串生成的随机字节
     *@引发InvalidParamException(如果指定了错误的长度)。
     *@在失败时抛出异常。
     */
    public function generateRandomKey($length = 32)
    {
        if (!is_int($length)) {
            throw new \Exception('First parameter ($length) must be an integer');
        }

        if ($length < 1) {
            throw new \Exception('First parameter ($length) must be greater than 0');
        }

        // always use random_bytes() if it is available
        if (function_exists('random_bytes')) {
            return random_bytes($length);
        }

        // The recent LibreSSL RNGs are faster and likely better than /dev/urandom.
        // Parse OPENSSL_VERSION_TEXT because OPENSSL_VERSION_NUMBER is no use for LibreSSL.
        // https://bugs.php.net/bug.php?id=71143
        if ($this->_useLibreSSL === null) {
            $this->_useLibreSSL = defined('OPENSSL_VERSION_TEXT')
                && preg_match('{^LibreSSL (\d\d?)\.(\d\d?)\.(\d\d?)$}', OPENSSL_VERSION_TEXT, $matches)
                && (10000 * $matches[1]) + (100 * $matches[2]) + $matches[3] >= 20105;
        }

        // Since 5.4.0, openssl_random_pseudo_bytes() reads from CryptGenRandom on Windows instead
        // of using OpenSSL library. LibreSSL is OK everywhere but don't use OpenSSL on non-Windows.
        if ($this->_useLibreSSL
            || (
                DIRECTORY_SEPARATOR !== '/'
                && substr_compare(PHP_OS, 'win', 0, 3, true) === 0
                && function_exists('openssl_random_pseudo_bytes')
            )
        ) {
            $key = openssl_random_pseudo_bytes($length, $cryptoStrong);
            if ($cryptoStrong === false) {
                throw new \Exception(
                    'openssl_random_pseudo_bytes() set $crypto_strong false. Your PHP setup is insecure.'
                );
            }
            if ($key !== false && StringHelper::byteLength($key) === $length) {
                return $key;
            }
        }

        // mcrypt_create_iv() does not use libmcrypt. Since PHP 5.3.7 it directly reads
        // CryptGenRandom on Windows. Elsewhere it directly reads /dev/urandom.
        if (function_exists('mcrypt_create_iv')) {
            $key = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
            if (StringHelper::byteLength($key) === $length) {
                return $key;
            }
        }

        // If not on Windows, try to open a random device.
        if ($this->_randomFile === null && DIRECTORY_SEPARATOR === '/') {
            // urandom is a symlink to random on FreeBSD.
            $device = PHP_OS === 'FreeBSD' ? '/dev/random' : '/dev/urandom';
            // Check random device for special character device protection mode. Use lstat()
            // instead of stat() in case an attacker arranges a symlink to a fake device.
            $lstat = @lstat($device);
            if ($lstat !== false && ($lstat['mode'] & 0170000) === 020000) {
                $this->_randomFile = fopen($device, 'rb') ?: null;

                if (is_resource($this->_randomFile)) {
                    // Reduce PHP stream buffer from default 8192 bytes to optimize data
                    // transfer from the random device for smaller values of $length.
                    // This also helps to keep future randoms out of user memory space.
                    $bufferSize = 8;

                    if (function_exists('stream_set_read_buffer')) {
                        stream_set_read_buffer($this->_randomFile, $bufferSize);
                    }
                    // stream_set_read_buffer() isn't implemented on HHVM
                    if (function_exists('stream_set_chunk_size')) {
                        stream_set_chunk_size($this->_randomFile, $bufferSize);
                    }
                }
            }
        }

        if (is_resource($this->_randomFile)) {
            $buffer = '';
            $stillNeed = $length;
            while ($stillNeed > 0) {
                $someBytes = fread($this->_randomFile, $stillNeed);
                if ($someBytes === false) {
                    break;
                }
                $buffer .= $someBytes;
                $stillNeed -= StringHelper::byteLength($someBytes);
                if ($stillNeed === 0) {
                    // Leaving file pointer open in order to make next generation faster by reusing it.
                    return $buffer;
                }
            }
            fclose($this->_randomFile);
            $this->_randomFile = null;
        }

        throw new \Exception('Unable to generate a random key');
    }

    /**
     * 生成指定长度的随机字符串。
     * 生成的字符串匹配[A-Za-Z0-9_-]，并且对URL编码是透明的。
     *@param int$ength键的长度(以字符表示)
     *@返回字符串生成的随机键
     *@在失败时抛出异常。
     */
    public function generateRandomString($length = 32)
    {
        if (!is_int($length)) {
            throw new \Exception('First parameter ($length) must be an integer');
        }

        if ($length < 1) {
            throw new \Exception('First parameter ($length) must be greater than 0');
        }

        $bytes = $this->generateRandomKey($length);
        return substr(StringHelper::base64UrlEncode($bytes), 0, $length);
    }

    /**
     *
     * 从密码和随机盐生成安全散列。
     *
     *生成的散列可以存储在数据库中。
     *稍后，当需要验证密码时，可以获取和传递哈希
     *至[[valdatePassword()]]。例如，
     *
     *```php
     *生成散列(通常在用户注册或密码更改时完成)
     *...在数据库中保存$Hash...
     *
     *登录期间，使用从数据库获取的$散列验证输入的密码是否正确
     ...
     *密码是好的
     *}其他{
     *密码错误
     *}
     *```
     @param字符串$密码，密码将被散列。
     @Param int$Cost参数由Blowfish哈希算法使用。
     *成本价值越高，
     *产生散列和验证密码所需的时间越长。高成本
     *因此减缓了一次野蛮的攻击。为了防止暴力袭击，
     *将其设置为生产服务器上允许的最高值。花在
     *计算每增加一次的哈希值，每增加一次$成本。
     *@返回字符串密码哈希字符串。当[[passwordHashStrategy]]被设置为“crypt”时，
     *当设置为“Password_散列”输出长度时，输出始终为60个ASCII字符
     ...
     *@对错误的密码参数或成本参数抛出异常。
     *@请参见valdatePassword()
     */
    public function generatePasswordHash($password, $cost = null)
    {
        if ($cost === null) {
            $cost = $this->passwordHashCost;
        }

        if (function_exists('password_hash')) {
            /* @noinspection PhpUndefinedConstantInspection */
            return password_hash($password, PASSWORD_DEFAULT, ['cost' => $cost]);
        }

        $salt = $this->generateSalt($cost);
        $hash = crypt($password, $salt);
        // strlen() is safe since crypt() returns only ascii
        if (!is_string($hash) || strlen($hash) !== 60) {
            throw new \Exception('Unknown error occurred while generating hash.');
        }

        return $hash;
    }

    /**
     * 根据散列验证密码。
     *@param string $password 用于验证密码。
     *@param string $hash 用于验证密码。
     *@返回bool密码是否正确。
     *@抛出错误的密码/散列参数或如果没有Blowfish散列的crypt()，则抛出InvalidParamException。
     *@见generatePasswordHash() string
     */
    public function validatePassword($password, $hash)
    {
        if (!is_string($password) || $password === '') {
            throw new \Exception('Password must be a string and cannot be empty.');
        }

        if (!preg_match('/^\$2[axy]\$(\d\d)\$[\.\/0-9A-Za-z]{22}/', $hash, $matches)
            || $matches[1] < 4
            || $matches[1] > 30
        ) {
            throw new \Exception('Hash is invalid.');
        }

        if (function_exists('password_verify')) {
            return password_verify($password, $hash);
        }

        $test = crypt($password, $hash);
        $n = strlen($test);
        if ($n !== 60) {
            return false;
        }

        return $this->compareString($test, $hash);
    }

    /**
     * 生成可用于生成密码散列的盐类。
     *
    ...
     *对于Blowfish哈希算法，需要一个特定格式的盐字符串：
     *“$2a$”、“$2x$”或“$2y$”，这是一个两位数的成本参数“$”和22个字符
     *从字母表“./0-9A-Za-z”。
     *
     *@param int$成本参数
     *@返回随机盐值字符串。
     *@引发InvalidParamException，如果成本参数超出4到31的范围。
     */
    protected function generateSalt($cost = 13)
    {
        $cost = (int) $cost;
        if ($cost < 4 || $cost > 31) {
            throw new \Exception('Cost must be between 4 and 31.');
        }

        // Get a 20-byte random string
        $rand = $this->generateRandomKey(20);
        // Form the prefix that specifies Blowfish (bcrypt) algorithm and cost parameter.
        $salt = sprintf('$2y$%02d$', $cost);
        // Append the random salt data in the required base64 format.
        $salt .= str_replace('+', '.', substr(base64_encode($rand), 0, 22));

        return $salt;
    }

    /**
     * 使用时间攻击抵抗方法执行字符串比较。
     *“看http://codereview.stackexchange.com/questions/13512
     * @$expected 将字符串比较。
     * @$actual 实际用户提供的字符串。
     * @返回bool是否字符串是否相等。
     */
    public function compareString($expected, $actual)
    {
        $expected .= "\0";
        $actual .= "\0";
        $expectedLength = StringHelper::byteLength($expected);
        $actualLength = StringHelper::byteLength($actual);
        $diff = $expectedLength - $actualLength;
        for ($i = 0; $i < $actualLength; $i++) {
            $diff |= (ord($actual[$i]) ^ ord($expected[$i % $expectedLength]));
        }

        return $diff === 0;
    }

    /**
     * 面具令牌使它不可。
     *适用于随机掩码的令牌和预备用于结果字符串总是独特的面具。
     *用于减轻违约如何攻击随机令牌在每个请求输出。
     * $token 令牌一揭露的令牌。
     *返回字符串一个蒙面令牌。
     */
    public function maskToken($token)
    {
        $mask = $this->generateRandomKey(StringHelper::byteLength($token));
        return StringHelper::base64UrlEncode($mask . ($mask ^ $token));
    }

    /**
     * 揭开先前被“maskToken”掩盖的令牌。
     *@param string $sugged Token一个蒙面令牌。
     *@返回string 一个未隐藏的令牌，或者在令牌格式无效的情况下返回空字符串。
     */
    public function unmaskToken($maskedToken)
    {
        $decoded = StringHelper::base64UrlDecode($maskedToken);
        $length = StringHelper::byteLength($decoded) / 2;
        if (!is_int($length)) {
            return '';
        }

        return StringHelper::byteSubstr($decoded, $length, $length) ^ StringHelper::byteSubstr($decoded, 0, $length);
    }



}