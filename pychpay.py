#-*- coding:utf-8 -*-
# author: wbsking

import hashlib

import pyDes


#商户交易请求URL
TRADE_URL = "http://sfj.chinapay.com/dac/sinpayservletGBK"
#交易结果查询URL
PAY_QUERY_URL = "http://sfj.chinapay.com/dac/SinPayQueryServletGBK"
#退单查询URL
FAIL_TRADE_QUERY_URL = "http://sfj.chinapay.com/dac/FailureTradeQueryGBK"
#备付金查询URL
BALANCE_QUERY_URL = "http://sfj.chinapay.com/dac/BalanceQueryGBK"

###################### 下面为测试环境的URL配置 ################################
#    #商户交易请求URL
#    DEAL_URL = "http://sfj-test.chinapay.com/dac/sinpayservletGBK"
#    #交易结果查询URL
#    PAY_QUERY_URL = "http://sfj-test.chinapay.com/dac/SinPayQueryServletGBK"
#    #退单查询URL
#    FAIL_TRADE_QUERY_URL = "http://sfj-test.chinapay.com/dac/FailureTradeQueryGBK"
#    #备付金查询URL
#    BALANCE_QUERY_URL = "http://sfj-test.chinapay.com/dac/BalanceQueryGBK"


DES_KEY = "SCUBEPGW"
HASH_PAD = "0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a05000414"


########################私钥信息###########################################
#15位商户号
MERID = 123456789012345

#银行提供的私钥
PRIVATE_KEY_S = ""


#银行提供的私钥(本接口中未使用)
PRIVATE_KEY_E = ""


########################公钥信息###########################################
#公钥账号
PGID = 999999999999999

#银行提供的公钥
PUB_KEY_S = ""

#银行提供的公钥(本文件中未使用)
PUB_KEY_E = ""


PRIVATE_KEY_INFO = {}
PUB_KEY_INFO = {}


def hex2bin(hexdata):
    bindata = ""
    if len(hexdata) % 2 == 1:
        hexdata = "0" + hexdata

    for i in range(0, len(hexdata), 2):
        bindata += chr(int(hexdata[i:i+2], 16))

    return bindata


def pad_str(src, total_len=256, pad_chr="0", d="L"):
    """将字符串补充至256位"""
    ret = src.strip()
    pad_len = total_len - len(ret)
    if pad_len > 0:
        pad = pad_chr * pad_len
        if d == "L":
            ret = pad + ret
        else:
            ret = ret + pad
    return ret


def bin2int(bindata):
    hexdata = bindata.encode('hex')
    return bchexdec(hexdata)


def bchexdec(hexdata):
    ret = 0
    hex_len = len(hexdata)
    for i in range(hex_len):
        hex_str = hexdata[i]
        dec = int(hex_str, 16)
        exp = hex_len - i - 1
        _pow = pow(16, exp)
        tmp = dec * _pow
        ret += tmp
    return str(ret)


def bcdechex(decdata):
    s = decdata
    ret = ""
    while s:
        m = int(s) % 16
        s = int(s) / 16
        hex_str = "%x" % m
        ret = hex_str + ret
    return ret


def sha1_128(msg):
    hash_value = hashlib.sha1(msg).hexdigest()
    return hex2bin(HASH_PAD) + hex2bin(hash_value)


def mybcpowmod(num, pow_str, mod):
    return pow(num, int(pow_str), mod)


def rsa_encrypt(private_key_info, enc_str):
    p = bin2int(private_key_info['prime1'])
    q = bin2int(private_key_info['prime2'])
    u = bin2int(private_key_info['coefficient'])
    dP = bin2int(private_key_info['prime_exponent1'])
    dQ = bin2int(private_key_info['prime_exponent2'])
    c = bin2int(enc_str)
    cp = int(c) % int(p)
    cq = int(c) % int(q)
    a = pow(cp, int(dP), int(p))
    b = pow(cq, int(dQ), int(q))
    if a >= b:
        result = a - b
    else:
        result = b - a
        result = int(p) - result
    result = result % int(p)
    result = result * int(u)
    result = result % int(p)
    result = result * int(q)
    result = result + int(b)
    ret = bcdechex(result)
    ret = pad_str(ret).upper()
    return ret if len(ret) == 256 else False


def rsa_decrypt(key_info, dec_str):
    check = bchexdec(dec_str)
    modulus = bin2int(key_info['modulus'])
    exponent = bchexdec("010001")
    result = pow(int(check), int(exponent), int(modulus))
    rb = bcdechex(result)
    return pad_str(rb).upper()


def sign(msg):
    hb = sha1_128(msg)
    return rsa_encrypt(PRIVATE_KEY_INFO, hb)


def sign_order(merid, ordno, amount, curyid, transdate, transtype):
    if not check_params(merid, ordno, amount, curyid, transdate, transtype):
        return False
    plain = merid + ordno + amount + curyid + transdate + transtype
    return sign(plain)


def verify(plain, check):
    if len(check) != 256:
        return False
    hb = sha1_128(plain)
    hbhex = hb.encode("hex").upper()
    rbhex = rsa_decrypt(PUB_KEY_INFO, check)
    print hbhex
    print rbhex
    return True if hbhex == rbhex else False


def verify_response(merid, ordno, amount, curyid, transdate, transtype, ordstatus, check):
    if not check_params(merid, ordno, amount, curyid, transdate, transtype):
        return False
    plain = merid + ordno + amount + curyid + transdate + transtype + ordstatus
    return verify(plain, check)


def check_params(merid, ordno, amount, curyid, transdate, transtype):
    if len(merid) != 15:
        return False
    if len(ordno) != 16:
        return False
    if len(amount) != 12:
        return False
    if len(curyid) != 3:
        return False
    if len(transdate) != 8:
        return False
    if len(transtype) != 4:
        return False
    return True


def build_private_key_info():
    """ 生成私钥信息用于加密 """
    PRIVATE_KEY_INFO['MERID'] = MERID
    hex_str = PRIVATE_KEY_S[80:]
    _build_key(PRIVATE_KEY_INFO, hex_str)


def build_pub_key_info():
    """生成公钥信息，用户验证签名"""
    PUB_KEY_INFO['PGID'] = PGID
    hex_str = PUB_KEY_S[48:]
    _build_key(PUB_KEY_INFO, hex_str)


def _build_key(key_info, hex_str):
    bin_str = hex2bin(hex_str)
    key_info['modulus'] = bin_str[0:128]
    iv = "\x00"*8

    prime1 = bin_str[384:448]
    enc_des = pyDes.des(DES_KEY, pyDes.CBC, iv)
    key_info['prime1'] = enc_des.decrypt(prime1)

    prime2 = bin_str[448:512]
    enc_des = pyDes.des(DES_KEY, pyDes.CBC, iv)
    key_info['prime2'] = enc_des.decrypt(prime2)

    exponent1 = bin_str[512:576]
    enc_des = pyDes.des(DES_KEY, pyDes.CBC, iv)
    key_info['prime_exponent1'] = enc_des.decrypt(exponent1)

    exponent2 = bin_str[576:640]
    enc_des = pyDes.des(DES_KEY, pyDes.CBC, iv)
    key_info['prime_exponent2'] = enc_des.decrypt(exponent2)

    coefficient = bin_str[640:704]
    enc_des = pyDes.des(DES_KEY, pyDes.CBC, iv)
    key_info['coefficient'] = enc_des.decrypt(coefficient)

build_pub_key_info()
build_private_key_info()


if __name__ == "__main__":
    check = sign("1234")
