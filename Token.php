<?php
// +----------------------------------------------------------------------
// | LIKE [ JUST DO IT ]
// +----------------------------------------------------------------------
// | Author: Mr.hu <huhaiyang7788@163.com>
// +----------------------------------------------------------------------
// | DESC: 生成唯一可用的token
// +----------------------------------------------------------------------
// | Date Time: 2018/3/8 10:08
// +----------------------------------------------------------------------


namespace su\security;


class Token extends Base
{

    /**
     * 生成唯一的token值
     * Author: Mr.hu.
     * Return string
     */
    public static function createToken()
    {
        return md5(uniqid(true).mt_rand(100000,999999),false);
    }
}