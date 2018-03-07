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


class OpenSsl extends BaseCrypt
{

    public static function decrypt($data,$key,$method='AES-128-CBC')
    {
        if(false===parent::checkExtension('openssl')){
            throw new \Exception('请先安装openssl扩展');
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
    public static function encrypt($data,$key,$method='AES-128-CBC')
    {
        if(false===parent::checkExtension('openssl')){
            throw new \Exception('请先安装openssl扩展');
        }
        return openssl_encrypt($data,$method,$key);
    }

}