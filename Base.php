<?php
// +----------------------------------------------------------------------
// | LIKE [ JUST DO IT ]
// +----------------------------------------------------------------------
// | Author: Mr.hu <huhaiyang7788@163.com>
// +----------------------------------------------------------------------
// | DESC: 
// +----------------------------------------------------------------------
// | Date Time: 2018/3/6 15:24
// +----------------------------------------------------------------------


namespace su\security;


class Base
{
    const OPEN_SSL='确认已安装openssl扩展，并开启';
    const OPEN_HASH='确认已开启hash扩展';
    /**
     * 检查该扩展模块是否存在
     * Author: Mr.hu.
     * @param $extension_name
     * Return void
     */
    public static function checkExtension($extension_name)
    {
        return get_extension_funcs($extension_name)===false?false:true;
    }


    /**
     * 检查当前系统中的php版本是否大于最低版本号
     * Author: Mr.hu.
     * @param $version
     * Return mixed
     */
    public static function checkVersion($version)
    {
        return version_compare(PHP_VERSION,$version,'>=');
    }

}