<?php
// +----------------------------------------------------------------------
// | LIKE [ JUST DO IT ]
// +----------------------------------------------------------------------
// | Author: Mr.hu <huhaiyang7788@163.com>
// +----------------------------------------------------------------------
// | DESC: 针对密码的操作  对php的密码加密操作的封装。如果是跨语言使用加密，
// | 不推荐该方法。这种加密只是在php中实现的。不想是md5这样的标准加密
// +----------------------------------------------------------------------
// | Date Time: 2018/3/6 15:22
// +----------------------------------------------------------------------


namespace su\security;


class PasswordHash extends BaseCrypt
{

    //以下是在使用passwordhash中要使用到的常量
    //PASSWORD_BCRYPT
    //PASSWORD_DEFAULT


    /**
     * 返回关于使用
     * Author: Mr.hu.
     * @param $hash
     * Return array
     */
    public function get_pass_info($hash)
    {
        return password_get_info($hash);
    }


    /**
     * 用password_hash加密密码
     * Author: Mr.hu.
     * @param $password
     * @param int $algo
     * @param array $options
     * Return bool|string
     */
    public static function get_pass_hash($password,$algo=PASSWORD_BCRYPT,$options=[])
    {
        return password_hash($password,$algo,$options);
    }

    /**
     * 验证密码和保存的hash值是否一直
     * Author: Mr.hu.
     * @param $pass
     * @param $hash
     * Return bool|string
     */
    public static function verify_pass($pass,$hash)
    {
        return password_hash($pass,$hash);
    }


}