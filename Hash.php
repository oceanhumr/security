<?php
// +----------------------------------------------------------------------
// | LIKE [ JUST DO IT ]
// +----------------------------------------------------------------------
// | Author: Mr.hu <huhaiyang7788@163.com>
// +----------------------------------------------------------------------
// | DESC: 
// +----------------------------------------------------------------------
// | Date Time: 2018/3/6 17:10
// +----------------------------------------------------------------------


namespace su\security;


class Hash extends BaseCrypt
{


    /**
     * 获取已注册的哈希算法列表
     * Author: Mr.hu.
     * Return array
     */
    public static function get_algos()
    {
        return hash_algos();
    }


    /**
     * 比较两个hash是不是相等的。注意第二个是要确定是否正确的hash值
     * Author: Mr.hu.
     * @param $correct_hash
     * @param $user_hash
     * Return void
     */
    public static function verify_hash_equals($correct_hash,$user_hash)
    {
        return hash_equals($correct_hash,$user_hash);
    }


    /**
     * 对文件使用特定的key进行hash_hmac加密
     * Author: Mr.hu.
     * @param $file_path
     * @param $key 密钥
     * @param $algo 加密算法
     * @param bool $raw_output 是否是二进制   false则是16进制
     * Return string
     */
    public static function hmac_file ($file_path,$key='7eb2b5c37443418fc77c136dd20e859c',$algo='md5',$raw_output=false)
    {
        return hash_hmac_file($algo,$file_path,$key,$raw_output);
    }


    /**
     * 对数据进行hmac加密
     * Author: Mr.hu.
     * @param $data
     * @param string $key
     * @param string $algo
     * @param bool $raw_output
     * Return void
     */
    public static function hmac($data,$key='7eb2b5c37443418fc77c136dd20e859c',$algo='md5',$raw_output=false)
    {
        return hash_hmac($algo,$data,$key,$raw_output);
    }


    /**
     * 使用hash_pdkdf2对密码进行加密
     * Author: Mr.hu.
     * @param $password
     * @param $salt 进行导出时所使用的"盐"，这个值应该是随机生成的。
     * @param string $algo
     * @param int $iterations
     * @param int $length
     * @param bool $raw_output
     * Return void
     */
    public static function pbkdf2($password,$salt,$algo='md5',$iterations=100,$length=32,$raw_output=false)
    {
        return hash_pbkdf2($algo,$password,$salt,$iterations,$length,$raw_output);
    }


    /**
     * 生成hash值，不带密钥
     * Author: Mr.hu.
     * @param $data
     * @param string $algo
     * Return void
     */
    public static function hash_str($data,$algo='md5')
    {
        return hash($algo,$data);
    }


    /**
     * 对多组数据进行hash加密.带密钥
     * Author: Mr.hu.
     * @param array $values
     * @param string $algo
     * @param null $key
     * @param bool $raw_output
     * Return string
     */
    public static function hash_str_with_key($values=[],$algo='md5',$key=null,$raw_output=false)
    {

        if($key){
            $resource=hash_init($algo,HASH_HMAC,$key);
        }else{
            $resource=hash_init($algo);
        }

        foreach ($values as $v){
            hash_update($resource,$v);
        }

        return hash_final($resource,$raw_output);
    }


}