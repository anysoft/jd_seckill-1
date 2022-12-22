import random
import time
import requests
import functools
import json
import os
import pickle

from lxml import etree
from jd_logger import logger
from timer import Timer
from config import global_config
from concurrent.futures import ProcessPoolExecutor
from exception import SKException
from util import (
    parse_json,
    send_wechat,
    wait_some_time,
    response_status,
    save_image,
    convert_image,
    open_image,
    email
)


class SpiderSession:
    """
    Session相关操作
    """

    def __init__(self):
        self.cookies_dir_path = "./cookies/"
        self.user_agent = global_config.getRaw('config', 'user_agent_default')
        self.session = self._init_session()

    def _init_session(self):
        session = requests.session()
        session.headers = self.get_headers()
        return session

    def get_headers(self):
        return {"User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;"
                          "q=0.9,image/webp,image/apng,*/*;"
                          "q=0.8,application/signed-exchange;"
                          "v=b3",
                "Connection": "keep-alive"}

    def get_user_agent(self):
        return self.user_agent

    def get_session(self):
        """
        获取当前Session
        :return:
        """
        return self.session

    def get_cookies(self):
        """
        获取当前Cookies
        :return:
        """
        return self.get_session().cookies

    def set_cookies(self, cookies):
        self.session.cookies.update(cookies)

    def load_cookies_from_local(self, cookies_String):
        """
        从本地加载Cookie
        :return:
        """
        cookies_file = ''
        if not os.path.exists(self.cookies_dir_path):
            return False
        for name in os.listdir(self.cookies_dir_path):
            if name.endswith(".cookies"):
                cookies_file = '{}{}'.format(self.cookies_dir_path, name)
                break
        if cookies_file == '':
            return False
        with open(cookies_file, 'rb') as f:
            local_cookies = pickle.load(f)

        # self.set_cookies(local_cookies)

        # 扫描登录载入无效，使用app抓包cookie
        # update cookie by cookie str
        cookie_dict = {i.split("=", 1)[0]: i.split("=", 1)[-1] for i in cookies_String.split("; ")}
        cookiejar = requests.utils.cookiejar_from_dict(cookie_dict, cookiejar=None, overwrite=True)
        cookiejar.clear()
        for key in cookie_dict.keys():
            cookiejar.set(key, cookie_dict.get(key), domain='.jd.com', path='/')

        self.set_cookies(cookiejar)

    def save_cookies_to_local(self, cookie_file_name):
        """
        保存Cookie到本地
        :param cookie_file_name: 存放Cookie的文件名称
        :return:
        """
        cookies_file = '{}{}.cookies'.format(self.cookies_dir_path, cookie_file_name)
        directory = os.path.dirname(cookies_file)
        if not os.path.exists(directory):
            os.makedirs(directory)
        with open(cookies_file, 'wb') as f:
            pickle.dump(self.get_cookies(), f)


class QrLogin:
    """
    扫码登录
    """

    def __init__(self, spider_session: SpiderSession):
        """
        初始化扫码登录
        大致流程：
            1、访问登录二维码页面，获取Token
            2、使用Token获取票据
            3、校验票据
        :param spider_session:
        """
        self.qrcode_img_file = 'qr_code.png'

        self.spider_session = spider_session
        self.session = self.spider_session.get_session()

        self.is_login = True
        # self.refresh_login_status() # todo 注掉登录判断

    def refresh_login_status(self):
        """
        刷新是否登录状态
        :return:
        """
        self.is_login = self._validate_cookies()

    def _validate_cookies(self):
        """
        验证cookies是否有效（是否登陆）
        通过访问用户订单列表页进行判断：若未登录，将会重定向到登陆页面。
        :return: cookies是否有效 True/False
        """
        url = 'https://order.jd.com/center/list.action'
        payload = {
            'rid': str(int(time.time() * 1000)),
        }
        headers = {
            'User-Agent': global_config.getRaw('config', 'user_agent_jd'),
            'Referer': 'https://order.jd.com/center/list.action',
        }
        try:
            resp = self.session.get(url=url, params=payload, allow_redirects=False)
            if resp.status_code == requests.codes.OK:
                return True
        except Exception as e:
            logger.error("验证cookies是否有效发生异常", e)
        return False

    def _get_login_page(self):
        """
        获取PC端登录页面
        :return:
        """
        url = "https://passport.jd.com/new/login.aspx"
        page = self.session.get(url, headers=self.spider_session.get_headers())
        return page

    def _get_qrcode(self):
        """
        缓存并展示登录二维码
        :return:
        """
        url = 'https://qr.m.jd.com/show'
        payload = {
            'appid': 133,
            'size': 147,
            't': str(int(time.time() * 1000)),
        }
        headers = {
            'User-Agent': self.spider_session.get_user_agent(),
            'Referer': 'https://passport.jd.com/new/login.aspx',
        }
        resp = self.session.get(url=url, headers=headers, params=payload)

        if not response_status(resp):
            logger.info('获取二维码失败')
            return False

        save_image(resp, self.qrcode_img_file)

        new_file_name = 'QRcode.jpg'
        convert_image(self.qrcode_img_file, new_file_name)
        open_image(new_file_name)

        logger.info('二维码获取成功，请打开京东APP扫描')
        # open_image(self.qrcode_img_file)
        if global_config.getRaw('messenger', 'email_enable') == 'true':
            email.send('二维码获取成功，请打开京东APP扫描', "<img src='cid:qr_code.png'>", [email.mail_user],
                       'qr_code.png')

        return True

    def _get_qrcode_ticket(self):
        """
        通过 token 获取票据
        :return:
        """
        url = 'https://qr.m.jd.com/check'
        payload = {
            'appid': '133',
            'callback': 'jQuery{}'.format(random.randint(1000000, 9999999)),
            'token': self.session.cookies.get('wlfstk_smdl'),
            '_': str(int(time.time() * 1000)),
        }
        headers = {
            'User-Agent': self.spider_session.get_user_agent(),
            'Referer': 'https://passport.jd.com/new/login.aspx',
        }
        resp = self.session.get(url=url, headers=headers, params=payload)

        if not response_status(resp):
            logger.error('获取二维码扫描结果异常')
            return False

        resp_json = parse_json(resp.text)
        if resp_json['code'] != 200:
            logger.info('Code: %s, Message: %s', resp_json['code'], resp_json['msg'])
            return None
        else:
            logger.info('已完成手机客户端确认')
            return resp_json['ticket']

    def _validate_qrcode_ticket(self, ticket):
        """
        通过已获取的票据进行校验
        :param ticket: 已获取的票据
        :return:
        """
        url = 'https://passport.jd.com/uc/qrCodeTicketValidation'
        headers = {
            'User-Agent': self.spider_session.get_user_agent(),
            'Referer': 'https://passport.jd.com/uc/login?ltype=logout',
        }

        resp = self.session.get(url=url, headers=headers, params={'t': ticket})
        if not response_status(resp):
            return False

        resp_json = json.loads(resp.text)
        if resp_json['returnCode'] == 0:
            return True
        else:
            logger.info(resp_json)
            return False

    def login_by_qrcode(self):
        """
        二维码登陆
        :return:
        """
        self._get_login_page()

        # download QR code
        if not self._get_qrcode():
            raise SKException('二维码下载失败')

        # get QR code ticket
        ticket = None
        retry_times = 85
        for _ in range(retry_times):
            ticket = self._get_qrcode_ticket()
            if ticket:
                break
            time.sleep(2)
        else:
            raise SKException('二维码过期，请重新获取扫描')

        # validate QR code ticket
        if not self._validate_qrcode_ticket(ticket):
            raise SKException('二维码信息校验失败')

        self.refresh_login_status()

        logger.info('二维码登录成功')


class JdSeckill(object):
    def __init__(self):
        self.cookies_String = global_config.getRaw('config', 'cookies_String')
        self.spider_session = SpiderSession()
        self.spider_session.load_cookies_from_local(self.cookies_String)

        # 登录状态标记
        self.qrlogin = QrLogin(self.spider_session)

        # 初始化信息
        self.sku_id = global_config.getRaw('config', 'sku_id')
        self.sku_gentoken_sign = global_config.getRaw('config', 'sku_gentoken_sign')
        self.user_agent_jd = global_config.getRaw('config', 'user_agent_jd')
        self.seckill_num = global_config.getRaw('config', 'seckill_num')
        self.timers = Timer()
        self.switch = True

        self.session = self.spider_session.get_session()

        self.user_agent = self.spider_session.user_agent
        self.nick_name = None

        self.api_headers = {
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': self.user_agent_jd,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,image/tpg,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'X-Requested-With': 'com.jingdong.app.mall',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        }

    def login_by_qrcode(self):
        """
        二维码登陆
        :return:
        """
        if self.qrlogin.is_login:
            logger.info('登录成功')
            return

        self.qrlogin.login_by_qrcode()

        if self.qrlogin.is_login:
            self.nick_name = self.get_username()
            self.spider_session.save_cookies_to_local(self.nick_name)
        else:
            raise SKException("二维码登录失败！")

    def check_login(func):
        """
        用户登陆态校验装饰器。若用户未登陆，则调用扫码登陆
        """

        @functools.wraps(func)
        def new_func(self, *args, **kwargs):
            if not self.qrlogin.is_login:
                logger.info("{0} 需登陆后调用，开始扫码登陆".format(func.__name__))
                self.login_by_qrcode()
            return func(self, *args, **kwargs)

        return new_func

    @check_login
    def reserve(self):
        """
        预约
        """
        self._reserve()

    @check_login
    def seckill(self):
        """
        抢购
        """
        self._seckill()

    @check_login
    def seckill_by_proc_pool(self, work_count=5):
        """
        多进程进行抢购
        work_count：进程数量
        """
        with ProcessPoolExecutor(work_count) as pool:
            for i in range(work_count):
                pool.submit(self.seckill)

    def _reserve(self):
        """
        预约
        """
        while True:
            try:
                self.make_reserve()
                break
            except Exception as e:
                logger.info('预约发生异常!', e)
            wait_some_time()

    def _seckill(self):
        """
        抢购
        """
        while self.switch:
            try:
                # 流程获取抢购页面
                """访问商品的抢购链接（用于设置cookie等"""
                # 获取用户名
                # logger.info('用户:{}'.format(self.get_username()))
                # 访问商品主页面
                # logger.info('商品名称:{}'.format(self.get_sku_title()))
                self.timers.start()

                logger.info('开始抢购:{}'.format(self.sku_id))

                # 1. 通过 genToken 获取 tokenKey
                # 获取 tokenKey，# todo 目前 sku_gentoken_sign 固化，后续可以根据抢购结果，针对不同skuId 进行配置
                token_key = self.gen_token(self.sku_id, self.sku_gentoken_sign)

                # 2. 获取抢购页面
                """获取商品的抢购链接
                点击"抢购"按钮后，会有两次302跳转，最后到达订单结算页面
                这里返回第一次跳转后的页面url，作为商品的抢购链接
                :return: 商品的抢购链接
                """
                divide_url = self.appjmp(token_key)
                capcha_url = self.divide_rediect(divide_url)
                if capcha_url:
                    seckill_url = self.capcha_rediect(capcha_url)
                    if seckill_url:
                        # 3. 访问抢购页面
                        self.request_seckill_checkout_page(seckill_url)
                        # 访问 tak js
                        self.get_tak_js()

                        # 4. 准备数据提交订单
                        # init 订单数据两次(第一次不包含准确数量和收货地区id，第二次才包含)
                        seckill_init_info = self.seckill_init_action(seckill_url)
                        # 获取计算sk
                        sk = self.get_tak_sk()

                        # 5. 提交订单
                        self.submit_seckill_order(seckill_url, seckill_init_info, sk)
            except Exception as e:
                logger.info('抢购发生异常，稍后继续执行！', e)
            wait_some_time()
        if not self.switch:
            logger.info('抢购已经结束了！', e)



    def make_reserve(self):
        """商品预约"""
        # logger.info('商品名称:{}'.format(self.get_sku_title()))
        url = 'https://yushou.jd.com/youshouinfo.action?'
        payload = {
            'callback': '',
            'sku': self.sku_id,
            't': '0.8777584799349334',
        }
        headers = {
            'User-Agent': self.user_agent_jd,
            'Referer': 'https://item.jd.com/{}.html'.format(self.sku_id),
        }
        resp = self.session.get(url=url, params=payload, headers=headers)
        resp_json = parse_json(resp.text)
        reserve_url = resp_json.get('url')
        self.timers.start()
        while True:
            try:
                resp = self.session.get(url='https:' + reserve_url)
                logger.info('预约成功，已获得抢购资格 / 您已成功预约过了，无需重复预约')
                if global_config.getRaw('messenger', 'enable') == 'true':
                    success_message = "预约成功，已获得抢购资格 / 您已成功预约过了，无需重复预约"
                    send_wechat(success_message)
                break
            except Exception as e:
                logger.error('预约失败正在重试...')


    def get_username(self):
        """获取用户信息"""
        url = 'https://passport.jd.com/user/petName/getUserInfoForMiniJd.action'
        payload = {
            'callback': 'jQuery{}'.format(random.randint(1000000, 9999999)),
            '_': str(int(time.time() * 1000)),
        }
        headers = {
            'User-Agent': self.user_agent_jd,
            'Referer': 'https://order.jd.com/center/list.action',
        }

        resp = self.session.get(url=url, params=payload, headers=headers)

        try_count = 5
        while not resp.text.startswith("jQuery"):
            try_count = try_count - 1
            if try_count > 0:
                resp = self.session.get(url=url, params=payload, headers=headers)
            else:
                break
            wait_some_time()
        # 响应中包含了许多用户信息，现在在其中返回昵称
        # jQuery2381773({"imgUrl":"//storage.360buyimg.com/i.imageUpload/xxx.jpg","lastLoginTime":"","nickName":"xxx","plusStatus":"0","realName":"xxx","userLevel":x,"userScoreVO":{"accountScore":xx,"activityScore":xx,"consumptionScore":xxxxx,"default":false,"financeScore":xxx,"pin":"xxx","riskScore":x,"totalScore":xxxxx}})
        return parse_json(resp.text).get('nickName')


    def get_sku_title(self):
        """获取商品名称"""
        url = 'https://item.jd.com/{}.html'.format(global_config.getRaw('config', 'sku_id'))
        headers = {
            # 'Charset': 'UTF-8',
            # 'Accept': 'application/json, text/plain, */*',
            # 'Accept-Encoding': 'gzip,deflate',
            # 'X-Requested-With': 'com.jingdong.app.mall',
            'user-agent': self.user_agent_jd,
            # 'Cache-Control': 'no-cache',
            # 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        }
        resp = self.session.get(url, headers=headers)
        resp.encoding = 'utf-8'
        x_data = etree.HTML(resp.text)
        sku_title = x_data.xpath('/html/head/title/text()')
        return sku_title[0]


    def gen_token(self, sku_id='', sign=''):
        """获取商品链接 token
        genToken 需要签名，签名是app端so进行sign的，目前不确认签名是否绑定商品，当前直接固化抓包签名
        :return: tokenKey
        """
        sku_gentoken_sign = 'st=1670896876203&sign=2428d51fad6737f692e1f6346d6d26b2'
        url = "https://api.m.jd.com/client.action?functionId=genToken&lmt=0&clientVersion=11.3.4&build=98481&client=android&partner=huaweiharmony&oaid=00000000-0000-0000-0000-000000000000&eid=eidA42eb81235dsfKxhvn2cBQiuEow5jffj8lSsYcRnb9x8JclvRQmCJw9cX7cgTOA8ThWppa4K54YTrQmOBISb3v2NRkDz6LAlqTgIoyjSUHK+dbdJm&sdkVersion=29&lang=zh_CN&harmonyOs=1&networkType=wifi&uts=0f31TVRjBSvs0XU%2FXCixtjX9Ak4iuD2e7Cv%2BveA4GVnybr3jSqw1PmMJHeSxG3Bydp%2FzVa%2FfzFUdcvgFVUcezNq1D1Hw6cWtzr3I7liXKPTOOumqrtzA9FnbVdI4MB46RJtdHyIsP4dO7Mlc7MTcl0v7Gg0%2FqSUQKQdIg0NV0yaNz%2FR1gmSRUFT5Fo9Ou3jBnwbLyZ0Ortpzot5o3fGp6w%3D%3D&uemps=0-2&ext=%7B%22prstate%22%3A%220%22%2C%22pvcStu%22%3A%221%22%7D&avifSupport=1&acs=1&ef=1&ep=%7B%22hdid%22%3A%22JM9F1ywUPwflvMIpYPok0tt5k9kW4ArJEU3lfLhxBqw%3D%22%2C%22ts%22%3A1670896875729%2C%22ridx%22%3A-1%2C%22cipher%22%3A%7B%22area%22%3A%22CJvpCJYmD18zCJU1XzYyCJSm%22%2C%22d_model%22%3A%22I1TABVcmEG%3D%3D%22%2C%22wifiBssid%22%3A%22dW5hbw93bq%3D%3D%22%2C%22osVersion%22%3A%22CJK%3D%22%2C%22d_brand%22%3A%22IPVLV0VT%22%2C%22screen%22%3A%22CtKmCMenCtKm%22%2C%22uuid%22%3A%22DtZtDJDtCQTtYJrrDJdrYm%3D%3D%22%2C%22aid%22%3A%22DtZtDJDtCQTtYJrrDJdrYm%3D%3D%22%2C%22openudid%22%3A%22DtZtDJDtCQTtYJrrDJdrYm%3D%3D%22%7D%2C%22ciphertype%22%3A5%2C%22version%22%3A%221.2.0%22%2C%22appname%22%3A%22com.jingdong.app.mall%22%7D&{}&sv=101".format(
            sku_gentoken_sign)
        payload = 'lmt=0&body=%7B%22to%22%3A%22https%253a%252f%252fplogin.m.jd.com%252fjd-mlogin%252fstatic%252fhtml%252fappjmp_blank.html%22%7D'

        sku_gentoken_sign = 'st=1670983276678&sign=7f55fa66852b315e7c417e03ef942724'
        url = 'https://api.m.jd.com/client.action?functionId=genToken&lmt=0&clientVersion=11.3.4&build=98481&client=android&partner=huaweiharmony&oaid=00000000-0000-0000-0000-000000000000&eid=eidA42eb81235dsfKxhvn2cBQiuEow5jffj8lSsYcRnb9x8JclvRQmCJw9cX7cgTOA8ThWppa4K54YTrQmOBISb3v2NRkDz6LAlqTgIoyjSUHK+dbdJm&sdkVersion=29&lang=zh_CN&harmonyOs=1&networkType=wifi&uts=0f31TVRjBSvs0XU%2FXCixtjX9Ak4iuD2eMWztysL9X3gwO5tV2U1pLfXpGVFyfGz94a%2FoKcyQNOUl%2B0HsTm8OWsOUKpjPKcn29AH9xeCaeZjrcaJXQj%2F8RhehnmSQnR3B5CHnRFLRz5cQIusq0Of6zORTAq2x2s9xizUDCd3fEIffqgSbvhKnL2P5ZarkUqu6WRo4ttIvVfyN4KbEPdFRQw%3D%3D&uemps=0-0&ext=%7B%22prstate%22%3A%220%22%2C%22pvcStu%22%3A%221%22%7D&avifSupport=1&acs=1&ef=1&ep=%7B%22hdid%22%3A%22JM9F1ywUPwflvMIpYPok0tt5k9kW4ArJEU3lfLhxBqw%3D%22%2C%22ts%22%3A1670982640602%2C%22ridx%22%3A-1%2C%22cipher%22%3A%7B%22area%22%3A%22CJvpCJYmD18zCJU1XzYyCJSm%22%2C%22d_model%22%3A%22I1TABVcmEG%3D%3D%22%2C%22wifiBssid%22%3A%22CJC5DzTvCJU4YwCyYwCmYtPtDWO3YJCmYJvsYJY3CNO%3D%22%2C%22osVersion%22%3A%22CJK%3D%22%2C%22d_brand%22%3A%22IPVLV0VT%22%2C%22screen%22%3A%22CtKmCMenCtKm%22%2C%22uuid%22%3A%22DtZtDJDtCQTtYJrrDJdrYm%3D%3D%22%2C%22aid%22%3A%22DtZtDJDtCQTtYJrrDJdrYm%3D%3D%22%2C%22openudid%22%3A%22DtZtDJDtCQTtYJrrDJdrYm%3D%3D%22%7D%2C%22ciphertype%22%3A5%2C%22version%22%3A%221.2.0%22%2C%22appname%22%3A%22com.jingdong.app.mall%22%7D&{}&sv=120'.format(
            sku_gentoken_sign)
        payload = 'lmt=0&body=%7B%22action%22%3A%22to%22%2C%22to%22%3A%22https%253A%252F%252Fdivide.jd.com%252Fuser_routing%253FskuId%253D2943430%22%7D&'

        headers = {
            'Charset': 'UTF-8',
            'Accept-Encoding': 'gzip,deflate',
            'user-agent': 'okhttp/3.12.1;jdmall;android;version/11.3.4;build/98481;',
            'Cache-Control': 'no-cache',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        }
        logger.info("在线获取 tokenKey....")
        resp = self.session.post(url=url, headers=headers, params=payload)
        # token.length =49 未登录 正常为71
        if resp.text and resp.text.__contains__('tokenKey') and len(json.loads(resp.text).get('tokenKey')) > 50:
            return parse_json(resp.text).get('tokenKey')
        else:
            logger.info("获取token失败")
            wait_some_time()
            raise SKException('token 获取失败，cookie失效，未登录或签名过期(需重新抓取genToken的sign)')


    def appjmp(self, token_key):
        url = 'https://un.m.jd.com/cgi-bin/app/appjmp?tokenKey={}&to=https://divide.jd.com/user_routing?skuId={}'.format(
            token_key, self.sku_id)
        rediect_url = self.api_get_redirect(url)
        if 'divide' in rediect_url:
            return rediect_url
        raise SKException('访问：{}  跳转：{}'.format(url, rediect_url))


    def divide_rediect(self, url):
        rediect_url = self.api_get_redirect(url)
        if 'captcha.html' in rediect_url:
            return rediect_url
        if 'Fail' in rediect_url:
            logger.info('抢购失败:{}'.format(rediect_url))
            return None
        raise SKException('访问：{}  跳转：{}'.format(url, rediect_url))


    def capcha_rediect(self, url):
        rediect_url = self.api_get_redirect(url)
        if 'seckill.action' in rediect_url and 'skuId' in rediect_url:
            logger.info('填写订单页面:{}'.format(rediect_url))
            return rediect_url
        if 'Fail' in rediect_url:
            logger.info('抢购失败:{}'.format(rediect_url))
            return None
        raise SKException('访问：{}  跳转：{}'.format(url, rediect_url))


    def api_get_redirect(self, url):
        # 跳转1 目的是三次跳转获取完整的cookie，如果 pt_key fake_开头表示未登录或者tokenKey错误
        logger.info("跳转流程:{}".format(url))
        payload = {}
        headers = self.api_headers
        resp = self.session.get(
            url=url,
            headers=headers,
            allow_redirects=False)
        if str(self.session.cookies.get('pt_key')).startswith('fake_'):
            logger.info("获取跳转链接失败，可能cookie失效识别为未登录 访问：{}  跳转：{}".format(url, resp.next.url))
            raise SKException('访问：{}  跳转：{}'.format(url, resp.next.url))
        return resp.next.url


    def request_seckill_checkout_page(self, url):
        """访问抢购订单结算页面"""
        logger.info('访问填写订单页面...')
        payload = {}
        headers = {
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': self.user_agent_jd,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,image/tpg,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'X-Requested-With': 'com.jingdong.app.mall',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7'
        }
        resp = self.session.get(url=url, params=payload, headers=headers, allow_redirects=False)
        if resp.text and resp.text.__contains__('tak.jd.com/a'):
            logger.info('成功进入填写订单页面，准备下单...')
        else:
            logger.info('抢购失败...')
            wait_some_time()


    def seckill_init_action(self, seckill_url, is_first_init=True, resp_json={}):
        """获取秒杀初始化信息（包括：地址，发票，token）
        :return: 初始化信息组成的dict
        """
        logger.info('init.action 初始化订单信息，第{}次 ...'.format(1 if is_first_init else 2))
        url = 'https://marathon.jd.com/seckillnew/orderService/init.action'
        payload = {
            'sku': self.sku_id,
            'num': self.seckill_num,
            'id': 0,
            'provinceId': 0,
            'cityId': 0,
            'countyId': 0,
            'townId': 0,
        }
        if not is_first_init:
            address = resp_json.get('address')
            payload = {
                'sku': self.sku_id,
                'num': self.seckill_num,
                'id': address.get('id'),
                'provinceId': address.get('provinceId'),
                'cityId': address.get('cityId'),
                'countyId': address.get('countyId'),
                'townId': address.get('townId'),
            }
        headers = {
            # 'User-Agent': self.user_agent,
            'User-Agent': self.user_agent_jd,
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://marathon.jd.com',
            'X-Requested-With': 'com.jingdong.app.mall',
            'Referer': seckill_url,
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        }
        resp = self.session.post(url=url, data=payload, headers=headers)
        logger.info('初始化订单信息{}'.format(resp.text))
        address_info = resp.text
        # if resp.text == 'null':
            # debug
        if address_info and address_info.__contains__('addressDetail'):
            resp_json = parse_json(address_info)
            # 初始化一次足以，返回结果一致，除了时间戳
            # if is_first_init:
            #     return self.seckill_init_action(seckill_url, False, resp_json)
            return resp_json
        else:
            if resp.text == 'null':
                # self.switch = False
                pass
            logger.info('初始化订单失败{}'.format(resp.text))
            raise SKException('初始化订单信息失败，返回信息:{}'.format(resp.text[0: 128]))


    def get_tak_js(self):
        url = 'https://tak.jd.com/a/tr.js?_t={}'.format(int(int(round(time.time() * 1000)) / 600000))
        payload = {}
        headers = {
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': self.user_agent_jd,
            'Accept': '*/*',
            'X-Requested-With': 'com.jingdong.app.mall',
            'Sec-Fetch-Site': 'same-site',
            'Sec-Fetch-Mode': 'no-cors',
            'Sec-Fetch-Dest': 'script',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7'
        }
        resp = self.session.get(url=url, params=payload, headers=headers, allow_redirects=False)
        if resp.text and resp.text.__contains__('var') and resp.text.__contains__('new'):
            logger.info('获取tak js 成功...')


    def get_tak_sk(self):
        url = 'https://tak.jd.com/t/871A9?_t={}'.format(int(int(round(time.time() * 1000))))
        headers = {
            'User-Agent': self.user_agent_jd,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': '*/*',
            'Origin': 'https://marathon.jd.com',
            'X-Requested-With': 'com.jingdong.app.mall',
            'Sec-Fetch-Site': 'same-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': 'https://marathon.jd.com/',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        }
        payload = {}
        logger.info('获取sk...')
        resp = self.session.get(url=url, data=payload, headers=headers)
        if resp.text and resp.text.__contains__("@t"):
            logger.info('获取sk成功...')
            return self.calc_sk(resp.text)
        logger.info('获取sk失败...')
        raise SKException('获取sk失败:{}'.format(resp.text[0: 128]))


    def submit_seckill_order(self, seckill_url, seckill_init_info, sk):
        """提交抢购（秒杀）订单
        :return: 抢购结果 True/False
        """
        url = 'https://marathon.jd.com/seckillnew/orderService/submitOrder.action?skuId={}'.format(self.sku_id)

        default_address = seckill_init_info['address']  # 默认地址dict
        invoice_info = seckill_init_info.get('invoiceInfo', {})  # 默认发票信息dict, 有可能不返回
        token = seckill_init_info['token']
        payload = {
            'num': self.seckill_num,
            'addressId': default_address['id'],
            'name': default_address['name'],
            'provinceId': default_address['provinceId'],
            'provinceName': default_address['provinceName'],
            'cityId': default_address['cityId'],
            'cityName': default_address['cityName'],
            'countyId': default_address['countyId'],
            'countyName': default_address['countyName'],
            'townId': default_address['townId'],
            'townName': default_address['townName'],
            'addressDetail': default_address['addressDetail'],
            'mobile': default_address['mobile'],
            'mobileKey': default_address['mobileKey'],
            'email': default_address.get('email', ''),
            'invoiceTitle': invoice_info.get('invoiceTitle', -1),
            'invoiceContent': invoice_info.get('invoiceContentType', 1),
            'invoicePhone': invoice_info.get('invoicePhone', ''),
            'invoicePhoneKey': invoice_info.get('invoicePhoneKey', ''),
            'invoice': 'true' if invoice_info else 'false',
            'password': global_config.get('account', 'payment_pwd'),
            'codTimeType': 3,
            'paymentType': 4,
            'overseas': 0,
            'phone': '',
            'areaCode': default_address.get('areaCode', ''),
            'token': token,
            'sk': sk,
            'skuId': self.sku_id,
        }

        logger.info('提交抢购订单...')
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'User-Agent': self.user_agent_jd,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://marathon.jd.com',
            'X-Requested-With': 'com.jingdong.app.mall',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': seckill_url,
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        }
        resp = self.session.post(
            url=url,
            data=payload,
            headers=headers)
        resp_json = None
        try:
            resp_json = parse_json(resp.text)
        except Exception as e:
            logger.info('抢购失败，返回信息:{}'.format(resp.text[0: 128]))
            return False
        # 返回信息
        # 抢购失败：
        # {'errorMessage': '很遗憾没有抢到，再接再厉哦。', 'orderId': 0, 'resultCode': 60074, 'skuId': 0, 'success': False}
        # {'errorMessage': '抱歉，您提交过快，请稍后再提交订单！', 'orderId': 0, 'resultCode': 60017, 'skuId': 0, 'success': False}
        # {'errorMessage': '系统正在开小差，请重试~~', 'orderId': 0, 'resultCode': 90013, 'skuId': 0, 'success': False}
        # 抢购成功：
        # {"appUrl":"xxxxx","orderId":820227xxxxx,"pcUrl":"xxxxx","resultCode":0,"skuId":0,"success":true,"totalMoney":"xxxxx"}
        if resp_json.get('success'):
            logger.info("成功信息：{}".format(resp_json))
            order_id = resp_json.get('orderId')
            total_money = resp_json.get('totalMoney')
            pay_url = 'https:' + resp_json.get('pcUrl')
            logger.info('抢购成功，订单号:{}, 总价:{}, 电脑端付款链接:{}'.format(order_id, total_money, pay_url))
            if global_config.getRaw('messenger', 'enable') == 'true':
                success_message = "抢购成功，订单号:{}, 总价:{}, 电脑端付款链接:{}".format(order_id, total_money, pay_url)
                send_wechat(success_message)
            return True
        else:
            logger.info('抢购失败，返回信息:{}'.format(resp_json))
            if global_config.getRaw('messenger', 'enable') == 'true':
                error_message = '抢购失败，返回信息:{}'.format(resp_json)
                send_wechat(error_message)
            return False


    def calc_sk(self, data):
        data = json.loads(data)
        data = data.get('data')
        keys = list(data)
        if data['@t'] == 'xa':
            return str(data[keys[1]])[1:16] + str(data[keys[5]])[4:10]
        if data['@t'] == 'cb':
            return str(data[keys[5]])[5:14] + str(data[keys[2]])[2:13].upper()
        if data['@t'] == 'ch':
            return str(data[keys[3]])[0:20].upper() + str(data[keys[4]])[6:10].upper()
        if data['@t'] == 'cbc':
            return str(data[keys[3]])[3:13].upper() + str(data[keys[2]])[10:19].lower()
        if data['@t'] == 'cca':
            return str(data[keys[2]])[14:19].lower() + str(data[keys[1]])[5:15].upper()
        if data['@t'] == 'by':
            return str(data[keys[1]])[5:8] + str(data[keys[2]])[0:20].replace('a', 'c')
        if data['@t'] == 'cza':
            return str(data[keys[3]])[6:19].lower() + str(data[keys[5]])[5:11]
        if data['@t'] == 'ab':
            return str(data[keys[4]])[10:18] + str(data[keys[5]])[2:13].lower()


if __name__ == '__main__':
    data = '{"code":"000000","message":"success","data":{"@t":"xa","hk":"qemYXr8aQIJfC5QRB9em","fG":"9xHdrUQSL0j2ovhdhZm3","Q":"Jm5ZRa6q8rvWHqOkpTLL","MP":"LeIvO9JLNuA8OwMh1w4Y","UP":"oae7wyljWbiy0juVqlnm"}}'
    data = '{"code":"000000","message":"success","data":{"@t":"cb","O":"s5w8iZ4WkU6bog6xmgcp","X":"h9xJvxmnGIgu7wgwMqXp","t":"IOabQBiUW9OMp7qyCF74","KZ":"yEyc3M0lPS80XJXJ6Yvl","F":"4GokdboZVFXenJ4Rjetg"}}'
    data = '{"code":"000000","message":"success","data":{"@t":"ch","ZlJ":"B9MlgQwH6oTjjxZOt4EC","I":"I6B0hRNnRPNVZL4Enbt3","Yt":"lFmCWHQaW5ageT75X3Qm","Qei":"UWPEOaE7L217R5Yu0yfg","p":"FcYBVsjDRERVqsSoLucV"}}'
    data = '{"code":"000000","message":"success","data":{"@t":"cbc","G":"seZPpJkh70ANSvd1bSPc","hST":"TQkilKmUsMD2mmD2iqxA","MPW":"H2ATmtFjl0YWyQOVX9kw","m":"gUItMAaVCSg95y6s8VqJ","Xm":"ZnhByWuAUFjCa3tpaDqO"}}'
    data = '{"code":"000000","message":"success","data":{"@t":"cca","dST":"dwq0iw97SgCsUUlxT61N","RKW":"rp2v4nZYujsIGSFDj15R","HB":"fmpS6P5ItC85T1tTuWYZ","sHq":"GMVlG7uOd4D9xDa17cIV","V":"pN53o0eIMKB4QFmQ289w"}}'
    data = '{"code":"000000","message":"success","data":{"@t":"by","KCx":"vuI0t8bs9XlTOIOuC1YD","A":"5F8SE1JdtikiTWLicHqd","VG":"T4lOCaHZ2KosKIDcUOtQ","dCI":"X0lq2hVp88BSo0Q3gDnj","kV":"Hxoj0fQ0dW6VnCZQ0PPo"}}'
    data = '{"code":"000000","message":"success","data":{"@t":"cza","T":"KedkNvaWjFBIkQRGYarX","bo":"JAguNOQuHMQs553TEuM1","ouh":"usqYoOKuPod760CFJrTX","Oo":"bdkDCT0I53NFDZv9NpUa","RDO":"gq7E1xiW1TBpYQkS1Ezl"}}'
    data = '{"code":"000000","message":"success","data":{"@t":"ab","wNp":"cAcKw24noz8Uu02qkzHs","aaj":"TBmboY43Z4BtzyTz0Fh2","LBG":"5Fe0BSajKV3pgnzUlUzT","VqV":"mFWDlwQbVeGxNSf5WYvH","QyX":"c759eeqczg2vSZoG2xgU"}}'

    s = JdSeckill()

    print(s.calc_sk(data))
