pychpay
=======

ChinaPay client for python!


pychpay是银联商户代付的python client，主要提供对字符串加密和验证签名的功能。


### 依赖

* PyDes
    安装： 
        
        pip install pyDes

### 使用
模块主要提供两个功能，加密和验证签名。

* 对数据加密
    
    ```python
        from pychpay import sign
        sign_str = sign("str_to_be_signed")
    ```
* 验证签名

    ```python
        from pychapy import verify
        plain = "xxxxxx"    # 待验证明文
        check = "xxxxxx"    # 待验证密文
        verify_result = verify(plain, check)
    ```

