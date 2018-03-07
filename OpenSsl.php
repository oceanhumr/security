<?php
// +----------------------------------------------------------------------
// | LIKE [ JUST DO IT ]
// +----------------------------------------------------------------------
// | Author: Mr.hu <huhaiyang7788@163.com>
// +----------------------------------------------------------------------
// | DESC: 基于openssl的加密方式
// +----------------------------------------------------------------------
// | Date Time: 2018/3/7 14:15
// +----------------------------------------------------------------------


namespace su\security;


class OpenSsl extends Base
{
    const EXTENSION_NAME='openssl';
    const DEFAULT_METHOD='AES-128-CBC';

    public static function decrypt($data,$key,$method=self::EXTENSION_NAME)
    {
        if(false===parent::checkExtension(static::EXTENSION_NAME)){
            throw new \Exception(static::OPEN_SSL);
        }
        return openssl_decrypt($data,$method,$key);
    }


    /**
     * 加密
     * Author: Mr.hu.
     * @param $data
     * @param $key
     * @param string $method
     * Return string
     */
    public static function encrypt($data,$key,$method=self::EXTENSION_NAME)
    {
        if(false===parent::checkExtension(static::EXTENSION_NAME)){
            throw new \Exception(static::OPEN_SSL);
        }
        return openssl_encrypt($data,$method,$key);
    }

}