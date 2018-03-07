<?php
// +----------------------------------------------------------------------
// | LIKE [ JUST DO IT ]
// +----------------------------------------------------------------------
// | Author: Mr.hu <huhaiyang7788@163.com>
// +----------------------------------------------------------------------
// | DESC: 加密操作
// +----------------------------------------------------------------------
// | Date Time: 2018/3/6 14:58
// +----------------------------------------------------------------------


namespace su\security;


class Cryptography extends Base
{

    /**
     * ascii转字符串
     * Author: Mr.hu.
     * @param $ascii
     * Return string
     */
    public static function ascii2str($ascii)
    {
        return chr($ascii);
    }


    /**
     * 字符串转ascii
     * Author: Mr.hu.
     * @param $str
     * Return int
     */
    public static function str2ascii($str)
    {
        return ord($str);
    }


    /**
     * 将所有（含二进制）字符串转化为可输出的字符
     * Author: Mr.hu.
     * @param string $str
     * Return void
     */
    public static function uuEncode($str)
    {
        return convert_uuencode($str);
    }


    /**
     * 解码使用uuencode之后的数据
     * Author: Mr.hu.
     * @param $str
     * Return void
     */
    public static function uuDecode($str)
    {
        return convert_uudecode($str);
    }


    /**
     * 使用 MIME base64 对数据进行编码
     * Author: Mr.hu.
     * @param $str
     * Return string
     */
    public static function base64Encode($str)
    {
        return base64_encode($str);
    }


    /**
     * 对使用 MIME base64 编码的数据进行解码
     * Author: Mr.hu.
     * @param $str
     * Return void
     */
    public static function base64Decode($str)
    {
        return base64_decode($str);
    }
    
    

    /**
     * 
     * 此字符串中除了 -_. 之外的所有非字母数字字符都将被替换成百分号（%）后跟两位十六进制数，空格则编码为加号（+）。
     * 此编码与 WWW 表单 POST 数据的编码方式是一样的，同时与 application/x-www-form-urlencoded 的媒体类型编码方式一样
     * （注意：将空格转为+）
     * Author: Mr.hu.
     * @param $url
     * Return string
     */
    public static function urlEncode($url)
    {
        return urlencode($url);
    }


    /**
     * 解码给出的已编码字符串中的任何 %##。 加号（'+'）被解码成一个空格字符
     * Author: Mr.hu.
     * @param $url
     * Return string
     */
    public static function urlDecode($url)
    {
        return urldecode($url);
    }


    /**
     * 对url进行转义编码 。
     * （注意：将空格转化为%20）
     * Author: Mr.hu.
     * @param $url
     * Return void
     */
    public static function rawUrlEncode($url)
    {
        return rawurlencode($url);
    }


    /**
     * 解密使用rawUrlEncode之后的数据
     * Author: Mr.hu.
     * @param $encode_data
     * Return string
     */
    public static function rawUrlDecode($encode_data)
    {
        return rawurldecode($encode_data);
    }


    /**
     * 数组转换成json字符串
     * Author: Mr.hu.
     * @param $arr
     * Return string
     */
    public static function jsonEncode($arr)
    {
        return json_encode($arr,JSON_UNESCAPED_UNICODE);
    }


    /**
     * json字符串转数组或者对象
     * Author: Mr.hu.
     * @param $json_str
     * @param bool $return_arr
     * Return mixed
     */
    public static function jsonDecode($json_str,$return_arr=true)
    {
        return json_decode($json_str,$return_arr);
    }


    /**
     * md5单项加密
     * Author: Mr.hu.
     * @param $str
     * @param bool $raw_output
     * Return void
     */
    public static function hMd5($str,$raw_output=false)
    {
        return md5($str,$raw_output);
    }


    /**
     *
     * Author: Mr.hu.
     * @param $file_path
     * @param bool $raw_output
     * Return string
     */
    public static function hMd5File($file_path,$raw_output=false)
    {

        if(!is_file($file_path)){
            throw new \Exception('无效文件');
        }
        return md5_file($file_path,$raw_output);
    }


    /**
     * 计算字符串的 sha1 散列值
     * Author: Mr.hu.
     * @param $str
     * @param bool $raw_output
     * Return void
     */
    public static function hSha1($str,$raw_output=false)
    {
        return sha1($str,$raw_output);
    }


    /**
     * 计算文件的 sha1 散列值
     * Author: Mr.hu.
     * @param $file_path
     * @param bool $raw_output
     * Return string
     */
    public static function hSha1File($file_path,$raw_output=false)
    {
        if(!is_file($file_path)){
            throw new \Exception('无效文件');
        }
        return sha1_file($file_path,$raw_output);
    }


}