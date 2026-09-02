import requests
import time
import base64
import json
import functools
import inspect
from urllib.parse import urlparse, parse_qs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from bs4 import BeautifulSoup
from . import ysu_login


class RuijieClient:
    """燕山大学锐捷V2网络认证客户端"""
    
    def __init__(self, proxies=None, verbose=False):
        """
        初始化锐捷客户端
        
        Args:
            proxies: 代理设置字典，格式如 {"http": "...", "https": "..."}
            verbose: 是否输出详细日志
        """
        self.client = requests.Session()
        self.proxies = proxies or {}
        self.verbose = verbose
        
        # 设置User-Agent
        self.client.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        })
        
        if self.proxies:
            self.client.proxies.update(self.proxies)
    
    def _log(self, message):
        """输出日志信息"""
        if self.verbose:
            print(f"[DEBUG] {message}")
    
    def _aes_encrypt_ecb(self, key_b64, plaintext):
        """
        AES-ECB-PKCS7加密（cas-sso登录使用）

        Args:
            key_b64: Base64编码的AES密钥
            plaintext: 明文字符串

        Returns:
            Base64编码的密文
        """
        key = base64.b64decode(key_b64)
        cipher = AES.new(key, AES.MODE_ECB)
        padded = pad(plaintext.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode('utf-8')

    def _unwrap_response(self, response, json_response=False):
        """
        解包响应结果
        
        Args:
            response: requests.Response对象
            json_response: 是否需要JSON响应处理
            
        Returns:
            响应数据或抛出异常
        """
        response.raise_for_status()
        
        if json_response:
            data = response.json()
            if data.get("code") == 200:
                return data.get("data")
            raise ValueError(f"API error: {data.get('message')}")
        
        return response.json()
    
    def get_online_user_info(self, session_id='114514'):
        """
        获取当前在线用户信息
        
        Args:
            session_id: 会话ID，检查状态时可以使用默认值
            
        Returns:
            用户在线信息字典
        """
        timestamp = int(time.time() * 1000)
        url = f"https://auth1.ysu.edu.cn/eportal/adaptor/getOnlineUserInfo?sessionId={session_id}&{timestamp}&version=this%20is%20a%20git-commit"
        
        response = self.client.get(url, proxies=self.proxies)
        return self._unwrap_response(response, json_response=True)
    
    def redirect_to_portal(self, redirect_url='https://auth1.ysu.edu.cn/eportal/redirect.jsp?mode=history'):
        """
        重定向到门户网站获取会话信息
        
        Args:
            redirect_url: 重定向URL
            
        Returns:
            包含sessionId等参数的字典
        """
        resp = self.client.get(redirect_url, allow_redirects=True, proxies=self.proxies, timeout=15)

        # 处理JavaScript重定向（最多重试两轮）
        for _ in range(2):
            if "location.href=" not in resp.text:
                break
            redirect_url_2 = resp.text.split("'")[1].split("'")[0]
            # 登出后服务端可能把页面指向哑地址（如 http://124.124.124.124），
            # 此时不要跟随，改为重新访问入口
            if "auth1.ysu.edu.cn" in redirect_url_2:
                resp = self.client.get(redirect_url_2, allow_redirects=True, proxies=self.proxies, timeout=15)
            else:
                self._log(f"Ignoring dead portal redirect: {redirect_url_2}")
                resp = self.client.get(redirect_url, allow_redirects=True, proxies=self.proxies, timeout=15)
        
        if "portal-main" not in resp.request.url:
            raise Exception(f"Portal redirection failed. Expected URL to contain 'portal-main', but got: {resp.request.url}")
        
        # 解析URL参数
        parsed_url = urlparse(resp.request.url)
        request_params = parse_qs(parsed_url.query)
        
        # 移除列表包装，只保留第一个值
        request_params = {k: v[0] for k, v in request_params.items()}
        
        return request_params
    
    def _get_current_node(self, session_info, flowKey='portal_auth'):
        """
        获取当前登录流程节点
        
        Args:
            session_info: 会话信息字典
            flowKey: 流程键
            
        Returns:
            当前节点信息
        """
        node_url = "https://auth1.ysu.edu.cn/eportal/workFlow/getCurrentNode"
        response = self.client.post(
            node_url,
            json={
                "sessionId": session_info['sessionId'],
                "flowKey": flowKey
            },
            proxies=self.proxies
        )
        
        node_resp = response.json()
        current_node = (node_resp.get('data') or {}).get('currentNodePath', 'Unknown')
        self._log(f"Current Node: {current_node}")
        
        return node_resp
    
    def cas_sso_login(self, username, password, session_info):
        """
        通过cas-sso直接登录（浏览器实际使用的流程）

        Args:
            username: 用户名
            password: 密码
            session_info: 会话信息字典

        Returns:
            bool: 登录是否成功
        """
        session_id = session_info.get('sessionId', '')
        custom_page_id = session_info.get('customPageId', '')
        nas_ip = session_info.get('nasIp', '')
        user_ip = session_info.get('userIp', '')
        ssid = session_info.get('ssid', '')
        mode = session_info.get('mode', '')

        timer = str(int(time.time() * 1000))
        cas_sso_url = (
            f"https://auth1.ysu.edu.cn/cas-sso/login?"
            f"flowSessionId={session_id}"
            f"&customPageId={custom_page_id}"
            f"&preview=false&appType=normal&language=zh-CN"
            f"&mode={mode}&timer={timer}"
            f"&nasIp={nas_ip}&userIp={user_ip}&ssid={ssid}"
        )

        # Step 1: GET cas-sso/login page to extract croypto and execution
        self._log(f"Fetching cas-sso login page...")
        resp = self.client.get(cas_sso_url, proxies=self.proxies)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, 'html.parser')

        croypto_el = soup.find('p', {'id': 'login-croypto'})
        flowkey_el = soup.find('p', {'id': 'login-page-flowkey'})

        if not croypto_el or not flowkey_el:
            raise Exception("Failed to extract croypto/flowkey from cas-sso page")

        croypto = croypto_el.get_text(strip=True)
        execution = flowkey_el.get_text(strip=True)
        self._log(f"Got croypto: {croypto[:20]}..., execution length: {len(execution)}")

        # Step 2: Encrypt password with AES-ECB
        encrypted_password = self._aes_encrypt_ecb(croypto, password)
        encrypted_captcha = self._aes_encrypt_ecb(croypto, '{}')

        # Step 3: POST login form
        post_url = cas_sso_url + "&accept-language=zh-CN"
        form_data = {
            'username': username,
            'type': 'UsernamePassword',
            '_eventId': 'submit',
            'geolocation': '',
            'execution': execution,
            'captcha_code': '',
            'croypto': croypto,
            'password': encrypted_password,
            'captcha_payload': encrypted_captcha,
        }

        self._log(f"Submitting cas-sso login form...")
        resp = self.client.post(
            post_url, data=form_data,
            allow_redirects=True,
            proxies=self.proxies
        )

        self._log(f"Login response URL: {resp.url}")

        # Check if we got redirected to auth-success.html with a ticket
        if 'auth-success' in resp.url or 'ticket=' in resp.url:
            self._log("CAS-SSO login succeeded (got ticket)")
            return True

        # Check for error in response
        if resp.status_code == 200:
            error_soup = BeautifulSoup(resp.text, 'html.parser')
            error_el = error_soup.find(id='errorMessage')
            if error_el:
                raise Exception(f"Login failed: {error_el.get_text(strip=True)}")

        raise Exception(f"CAS-SSO login failed, final URL: {resp.url}")

    def get_cas_login_url_v2(self):
        """
        通过访问portal获取CAS登录URL（新方法）

        当用户未认证时，访问portal会自动重定向到CAS登录页面

        Returns:
            CAS登录URL字符串，如果已认证则返回None
        """
        # 访问portal入口，不自动跟随重定向
        portal_url = "https://auth1.ysu.edu.cn/eportal/redirect.jsp?mode=history"
        resp = self.client.get(portal_url, allow_redirects=False, proxies=self.proxies)

        # 检查是否有重定向
        redirect_count = 0
        while resp.status_code in [301, 302, 303, 307, 308] and redirect_count < 10:
            location = resp.headers.get('Location')
            self._log(f"Redirect {redirect_count}: {location[:100] if location else 'None'}...")

            # 如果重定向到CAS登录页面，返回这个URL
            if location and 'cer.ysu.edu.cn/authserver/login' in location:
                self._log(f"Found CAS login URL: {location}")
                return location

            # 继续跟随重定向
            if location:
                resp = self.client.get(location, allow_redirects=False, proxies=self.proxies)
                redirect_count += 1
            else:
                break

        # 如果没有重定向到CAS，可能已经认证
        self._log(f"No CAS redirect found, final status: {resp.status_code}, URL: {resp.request.url}")
        return None

    def get_cas_login_url(self, session_info):
        """
        获取CAS登录URL（包含delegatedclientid）

        Args:
            session_info: 会话信息字典

        Returns:
            CAS登录URL字符串
        """
        session_id = session_info.get('sessionId', '')
        custom_page_id = session_info.get('customPageId', '')
        nas_ip = session_info.get('nasIp', '')
        user_ip = session_info.get('userIp', '')
        ssid = session_info.get('ssid', '')
        user_mac = session_info.get('userMac', '')

        # 首先POST到sam-sso/login
        sam_url = f"https://auth1.ysu.edu.cn/sam-sso/login?flowSessionId={session_id}&customPageId={custom_page_id}&preview=false&appType=normal&language=zh-CN&nasIp={nas_ip}&userIp={user_ip}&ssid={ssid}&userMac={user_mac}"
        resp = self.client.post(sam_url, json=session_info, proxies=self.proxies, allow_redirects=True)

        # 获取CAS重定向URL（不自动跟随重定向）
        cas_redirect_url = "https://auth1.ysu.edu.cn/sam-sso/clientredirect?client_name=sidadapter&service=https://auth1.ysu.edu.cn/portal/entry/pc/authenticate;flowParams=undefined;from="
        resp = self.client.get(cas_redirect_url, allow_redirects=False, proxies=self.proxies)

        # 检查是否有重定向
        if resp.status_code in [301, 302, 303, 307, 308]:
            cas_login_url = resp.headers.get('Location')
            if cas_login_url and 'cer.ysu.edu.cn' in cas_login_url:
                self._log(f"Got CAS login URL: {cas_login_url}")
                return cas_login_url

        # 如果没有重定向到CAS，可能已经有有效的ticket
        if "ticket=" in resp.request.url:
            self._log("Already have a valid ticket, no CAS login needed")
            return None

        raise Exception(f"Failed to get CAS login URL. Status: {resp.status_code}, URL: {resp.request.url}")

    def complete_sam_login(self, session_info):
        """
        完成SAM登录流程（在CAS认证之后）

        注意：CAS登录成功后会自动重定向到cas-sso/login，
        然后再重定向到authenticate页面，所以不需要手动调用clientredirect

        Args:
            session_info: 会话信息字典

        Returns:
            None
        """
        self._log("SAM login completed via CAS redirect chain")

        # 验证用户在线状态，确保会话已建立
        session_id = session_info.get('sessionId', '')
        user_info = self.get_online_user_info(session_id)
        self._log(f"User online info after authenticate: {user_info}")

        self._get_current_node(session_info)
    
    def service_selection(self, session_info):
        """
        获取可用服务列表
        
        Args:
            session_info: 会话信息字典
            
        Returns:
            服务选择响应数据
        """
        service_url = "https://auth1.ysu.edu.cn/eportal/network/serviceSelection"
        response = self.client.post(service_url, json={
            "sessionId": session_info['sessionId']
        }, proxies=self.proxies)
        
        self._get_current_node(session_info)
        return self._unwrap_response(response, json_response=True)
    
    def service_login(self, session_info, service="校园网"):
        """
        登录到指定服务
        
        Args:
            session_info: 会话信息字典
            service: 服务名称
            
        Returns:
            服务登录响应
        """
        service_url = "https://auth1.ysu.edu.cn/eportal/network/serviceLogin"
        response = self.client.post(service_url, json={
            "sessionId": session_info['sessionId'],
            "service": service
        }, proxies=self.proxies)
        
        self._get_current_node(session_info)
        return response.json()
    
    def user_online(self, session_info):
        """
        检查用户是否在线
        
        Args:
            session_info: 会话信息字典
            
        Returns:
            用户在线状态数据
        """
        online_url = "https://auth1.ysu.edu.cn/eportal/network/userOnline"
        response = self.client.post(online_url, json={
            "sessionId": session_info['sessionId']
        }, proxies=self.proxies)
        
        return self._unwrap_response(response, json_response=True)
    
    def get_account_info(self, session_info):
        """
        获取账户信息
        
        Args:
            session_info: 会话信息字典
            
        Returns:
            账户信息数据
        """
        account_url = "https://auth1.ysu.edu.cn/eportal/operator/getAccountInfo"
        response = self.client.post(account_url, json={
            "sessionId": session_info['sessionId']
        }, proxies=self.proxies)
        
        return self._unwrap_response(response, json_response=True)
    
    def offline(self, session_info):
        """
        用户登出
        
        Args:
            session_info: 会话信息字典
            
        Returns:
            登出响应数据
        """
        offline_url = "https://auth1.ysu.edu.cn/eportal/network/offline"
        response = self.client.post(offline_url, json={
            "sessionId": session_info['sessionId']
        }, proxies=self.proxies)
        
        return self._unwrap_response(response, json_response=True)
    
    def check_login_status(self):
        """
        检查当前登录状态
        
        Returns:
            tuple: (is_logged_in, user_info_or_redirect_url)
        """
        try:
            # 新版 eportal 使用伪造的 sessionId 查询会被判定为
            # dx.failed.user.offline，必须先走一次 portal 重定向拿真实 sessionId
            try:
                session_info = self.redirect_to_portal()
                session_id = session_info.get('sessionId', '114514')
            except Exception as e:
                self._log(f"Failed to get portal session, fallback to default: {e}")
                session_info, session_id = {}, '114514'

            is_online, user_info = self._query_online_status(session_info)
            portal_user = user_info.get("portalOnlineUserInfo", {})
            redirect_url = portal_user.get("redirectUrl")

            if is_online:
                # 已登录
                return True, user_info
            else:
                # 未登录
                return False, redirect_url
        except Exception as e:
            self._log(f"Error checking login status: {e}")
            return False, None

    def _query_online_status(self, session_info):
        """
        查询当前是否在线。

        不同 NAS 的行为不一致：
        - 宿舍区：portalOnlineUserInfo 查询成功时 result=success 且带 userId
        - 教学区 Ruijie：portalOnlineUserInfo 可能返回 result=fail，
         但 network/userOnline 仍然返回 online=true

        Returns:
            tuple: (is_online, user_info)
        """
        session_id = session_info.get('sessionId', '114514')
        user_info = self.get_online_user_info(session_id)
        portal_user = user_info.get("portalOnlineUserInfo") or {}
        redirect_url = portal_user.get("redirectUrl")

        is_online = (
            portal_user.get("result") == "success"
            and portal_user.get("userId")
            and not redirect_url
        )

        if not is_online:
            try:
                online_status = self.user_online(session_info)
                is_online = bool(online_status.get("online"))
            except Exception as e:
                self._log(f"userOnline check failed: {e}")
                # 兜底：portal 会话参数里直接带 userOnline=true
                is_online = str(session_info.get("userOnline", "")).lower() == "true"

        # 在线但 portalOnlineUserInfo 没有用户名时（教学区 NAS），
        # 尝试用账号信息补全，方便 status 展示
        if is_online and not portal_user.get("userName"):
            try:
                account = self.get_account_info(session_info) or {}
                if account.get("name"):
                    portal_user["userName"] = account["name"]
                if account.get("service"):
                    portal_user["service"] = account["service"]
            except Exception as e:
                self._log(f"getAccountInfo failed: {e}")

        return is_online, user_info
    
    def get_available_services(self, username, password):
        """
        获取可用服务列表（不执行登录）

        Args:
            username: 用户名
            password: 密码

        Returns:
            list: 可用服务列表
        """
        try:
            # 1. 检查当前状态
            is_logged_in, info = self.check_login_status()
            if is_logged_in:
                # 如果已登录，获取会话信息并查询服务
                session_info = self.redirect_to_portal()
                services = self.service_selection(session_info)
                return services

            # 2. 重定向到门户获取会话信息
            session_info = self.redirect_to_portal()
            self._log(f"Got session info: {session_info}")

            # 3. 通过cas-sso直接登录
            self.cas_sso_login(username, password, session_info)

            # 6. 获取服务列表
            services = self.service_selection(session_info)
            self._log(f"Available services: {services}")

            return services

        except Exception as e:
            if self.verbose:
                self._log(f"Get services failed: {e}")
            raise e

    def login(self, username, password, service="校园网"):
        """
        执行完整的登录流程

        Args:
            username: 用户名
            password: 密码
            service: 要登录的服务名称

        Returns:
            bool: 登录是否成功
        """
        try:
            # 1. 重定向到门户获取会话信息（并用真实 sessionId 检查在线状态）
            session_info = self.redirect_to_portal()
            self._log(f"Got session info: {session_info}")
            is_online, user_info = self._query_online_status(session_info)
            portal_user = user_info.get('portalOnlineUserInfo') or {}
            current_user_id = portal_user.get('userId')
            if is_online:
                current_user = portal_user.get('userName', 'unknown')
                current_service = portal_user.get('service') or 'unknown'
                if not current_user_id or current_user_id == username:
                    self._log(f"Already logged in as {current_user} ({current_service})")
                    return True
                # 教学区等共享出口 IP 的网段，portalOnlineUserInfo 显示的
                # 可能是同网段其他账号，因此只提示、不阻断
                print(
                    f"提示: 当前网络已在线（服务器显示账号 {current_user} / {current_service}）。"
                    f"如需确保切换到 {username} / {service}，请先执行 ysunetlogin logout 后重新登录。"
                )
                return True

            # 2. 通过cas-sso直接登录
            self.cas_sso_login(username, password, session_info)
            
            # 3. 获取服务列表
            services = self.service_selection(session_info)
            self._log(f"Available services: {services}")
            
            # 4. 登录到指定服务
            login_result = self.service_login(session_info, service)
            self._log(f"Service login result: {login_result}")

            # 5. 验证登录状态
            online_status = self.user_online(session_info)
            self._log(f"User online status: {online_status}")

            # 6. 已在线但工作流已结束时，服务端会返回 workFlowNode is empty；
            #    此时只要实际在线即视为成功
            if (
                login_result.get('code') != 200
                and 'workflownode is empty' in str(login_result.get('message', '')).lower()
                and online_status.get('online', False)
            ):
                self._log("Workflow already finished and user is online, treating as success")
                return True
            
            # 7. 检查认证结果
            if login_result.get('code') == 200 and login_result.get('data'):
                auth_result = login_result['data'].get('authResult')
                if auth_result == 'fail':
                    auth_message = login_result['data'].get('authMessage', 'Unknown authentication error')
                    raise Exception(f"Authentication failed: {auth_message}")
                elif auth_result != 'success':
                    raise Exception(f"Unexpected authentication result: {auth_result}")
            else:
                raise Exception(f"Invalid service login response: {login_result}")
            
            # 8. 检查在线状态
            if not online_status.get('online', False):
                error_message = online_status.get('message', 'User is not online after authentication')
                raise Exception(f"Login verification failed: {error_message}")
            
            return True
            
        except Exception as e:
            if self.verbose:
                self._log(f"Login failed: {e}")
            raise e
    
    def logout(self):
        """
        执行登出操作
        
        Returns:
            bool: 登出是否成功
        """
        try:
            # 1. 重定向到门户获取会话信息（并用真实 sessionId 检查在线状态，
            #    否则会误判“已登出”导致根本不会调用 offline）
            session_info = self.redirect_to_portal()
            self._log(f"Got session info for logout: {session_info}")

            is_logged_in, user_info = self._query_online_status(session_info)
            if not is_logged_in:
                self._log("Already logged out")
                return True
            
            # 2. 执行登出
            offline_result = self.offline(session_info)
            self._log(f"Offline result: {offline_result}")
            
            # 3. 验证登出状态
            final_status = self.user_online(session_info)
            self._log(f"Final user status: {final_status}")
            
            return True
            
        except Exception as e:
            if self.verbose:
                self._log(f"Logout failed: {e}")
            raise e
