package retirement;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import sun.misc.BASE64Decoder;

public class RetirementImpl implements RetirementService{

	public static void main(String[] args) throws Exception {
		RetirementImpl retirementImpl=new RetirementImpl();
		// 设置params属性
		String IDnumber = "";
		String Username = "";
		Retirement retirement=retirementImpl.HttpPostRetirement(Username, IDnumber);
		//System.out.println(retirement.toString());
	}

	/**
	 * @param Username,IDnumber
	 * @return Retirement
	 * @throws Exception
	 */
	public Retirement HttpPostRetirement(String Username, String IDnumber) throws Exception {

		// 获取当前时间
		String gateway_rtime = System.currentTimeMillis() + "";
		System.out.println("gateway_rtime:" + gateway_rtime);

		// app_key的值
		String app_key = "MTNhMzU1N2NkNmIxNDgyMzkyMTg0MjgzOTY5OWUzMTY6MTIzNDU2";

		// gateway_appid的值
		String gateway_appid = "13a3557cd6b14823921842839699e316";
		System.out.println("gateway_appid:" + gateway_appid);

		// 获取加密的sig的值
		String sign = gatewaySignEncode(gateway_appid, app_key, gateway_rtime);
		// System.out.println("加密的sig的值"+sign);

		// 设置请求的token地址
		String requestUrl = "http://59.207.34.166:8000/share/spthqsqlpnew";

		// 设置请求的方法
		String requestMethod = "POST";

		// 获得加密的token
		Object object = httpRequest(requestUrl, requestMethod, gateway_appid, gateway_rtime, sign);
		JSONObject obj = JSON.parseObject(object.toString());
		JSONObject obj1 = (JSONObject) obj.get("body");
		String token = (String) obj1.get("access_token");
		// System.out.println(token);

		// 根据加密的token获得serectKey
		String serectKey = AESDncode(app_key, token);
		// System.out.println(TokenInterface.AESDncode(app_key, token));

		// 根据serectKey获取
		String gateway_sig = gatewaySignEncode(gateway_appid, serectKey, gateway_rtime);
		System.out.println("gateway_sig的值：" + gateway_sig);

		// 创建一个httpclient对象
		CloseableHttpClient httpClient = HttpClients.createDefault();

		// 创建一个httppost请求对象，需要指定一个url
		// 请求url的地址
		String URL = "http://59.207.34.166:8000/share/rst_ltxryylbxxx";
		HttpPost post = new HttpPost(URL);

		// 设置header信息
		post.setHeader("gateway_sig", gateway_sig);
		post.setHeader("gateway_appid", gateway_appid);
		post.setHeader("gateway_rtime", gateway_rtime);

		// 设置参数信息
		List<NameValuePair> formList = new ArrayList<>();
		formList.add(new BasicNameValuePair("req.token", "dbb5c194f5bf4a54a00650e51147d0f4"));
		formList.add(new BasicNameValuePair("req.subscribeId", "9507c99af34245ac9af035b6ae58137a"));
		formList.add(new BasicNameValuePair("req.userId", "a81013f8571e4a77801d34914f49c207"));
		formList.add(new BasicNameValuePair("params[0].fieldCode", "AAC002"));
		formList.add(new BasicNameValuePair("params[0].operateCode", "="));
		formList.add(new BasicNameValuePair("params[0].parameterValue", IDnumber));
		formList.add(new BasicNameValuePair("params[1].fieldCode", "AAC003"));
		formList.add(new BasicNameValuePair("params[1].operateCode", "="));
		formList.add(new BasicNameValuePair("params[1].parameterValue", Username));

		// 需要把表单包装到Entity对象中。StringEntity
		StringEntity entity = new UrlEncodedFormEntity(formList, "utf-8");
		post.setEntity(entity);

		// 执行请求。
		CloseableHttpResponse response = httpClient.execute(post);

		// 接收返回结果
		HttpEntity httpEntity = response.getEntity();
		String result = EntityUtils.toString(httpEntity);
		//System.out.println(result);

		JSONObject jsonObject=JSON.parseObject(result.toString());
		JSONObject jsonObject1=JSON.parseObject(jsonObject.get("data").toString());
		JSONObject jsonObject2=JSON.parseObject(jsonObject1.get("data").toString());
		List list=(List) jsonObject2.get("list");
		//System.out.println(list.get(0));
		Retirement retirement=new Retirement();
		
		//获取身份证号
		String iDnumber=(String) JSON.parseObject(list.get(0).toString()).get("AAC002");
		retirement.setIDnumber(iDnumber);
		//System.out.println("身份证号为"+retirement.getIDnumber());
		
		//获取参保单位社保编号（单位编号）
		String unitnumber=(String) JSON.parseObject(list.get(0).toString()).get("AAB001");
		retirement.setUnitnumber(unitnumber);
		//System.out.println("单位编号为 "+retirement.getUnitnumber());
		
		//获取批次号
		String lotnumber=(String) JSON.parseObject(list.get(0).toString()).get("SDC_BATCH_NO");
		retirement.setLotnumber(lotnumber);
		//System.out.println("批次号 "+retirement.getLotnumber());
		
		//获取通过退休审批时间
		String approvaltime=(String) JSON.parseObject(list.get(0).toString()).get("AIC162");
		retirement.setApprovaltime(approvaltime);
		//System.out.println("通过退休审批时间为:"+retirement.getApprovaltime());
		
		//获得人员姓名
		String username=(String) JSON.parseObject(list.get(0).toString()).get("AAC003");
		retirement.setUsername(username);
		//System.out.println("人员姓名为："+retirement.getUsername());
		
		//获得参保地行政区划代码
		String entitycode=(String) JSON.parseObject(list.get(0).toString()).get("AAB301");
		retirement.setEntitycode(entitycode);
		//System.out.println("参保地行政区划代码:"+retirement.getEntitycode());
		
		//获得单位名称
		String unitname=(String) JSON.parseObject(list.get(0).toString()).get("AAB004");
		retirement.setUnitname(unitname);
		//System.out.println("单位名称为："+retirement.getUnitname());
		/*
		 * JSONObject jsonObject=JSON.parseObject(result.toString()); Object
		 * object1 =jsonObject.get("data"); System.out.println(object1);
		 */

		// 关闭流。
		response.close();
		httpClient.close();
		return retirement;
	}
	
	
	

	/**
	 * 密钥生成【核心网关】
	 * 
	 * @param appKey
	 *            授权码
	 * @param appId
	 *            请求者标识
	 * @param rtime
	 *            请求时间戳
	 * @return 加密后的sign，即head请求参数的gateway_sig
	 */
	public static String gatewaySignEncode(String appId, String appKey, String rtime) throws Exception {
		String inputString = appId + rtime;
		return encode(appKey, inputString);
	}

	private static String encode(String appKey, String inputStr) throws Exception {
		String sign;
		Mac hmacSha256 = Mac.getInstance("HmacSHA256");
		byte[] keyBytes = appKey.getBytes("UTF-8");
		hmacSha256.init(new SecretKeySpec(keyBytes, 0, keyBytes.length, "HmacSHA256"));
		byte[] hmacSha256Bytes = hmacSha256.doFinal(inputStr.getBytes("UTF-8"));
		sign = new String(Base64.encodeBase64(hmacSha256Bytes), "UTF-8");
		return sign;
	}

	/**
	 * http请求过程
	 * 
	 * @param requestUrl
	 *            请求的url，在服务调用过程中url为获取token的url（格式为ip:port/auth/token）
	 *            或者是服务调用的url
	 * @param requestMethod
	 *            获取token时，请求方法为POST；调用服务是请求方法依据服务注册时定义。
	 * @param appIdorSecretKey
	 *            获取token时该参数为appId；抵用服务时该参数为SecretKey
	 * @param currTime
	 *            该参数为当前时间
	 * @param sign
	 *            该参数为head参数gateway_sig，由秘钥生成方法gatewaySignEncode生成。
	 * @return
	 */
	public static JSONObject httpRequest(String requestUrl, String requestMethod, String appIdorSecretKey,
			String currTime, String sign) throws Exception {
		JSONObject jsonObject = null;
		StringBuffer buffer = new StringBuffer();
		InputStream inputStream = null;
		try {
			URL url = new URL(requestUrl);
			HttpURLConnection httpUrlConnection = (HttpURLConnection) url.openConnection();
			httpUrlConnection.setRequestMethod(requestMethod);
			httpUrlConnection.setDoOutput(true);
			httpUrlConnection.setDoInput(true);
			httpUrlConnection.setRequestProperty("gateway_appid", appIdorSecretKey);
			httpUrlConnection.setRequestProperty("gateway_rtime", currTime);
			httpUrlConnection.setRequestProperty("gateway_sig", sign);
			httpUrlConnection.connect();
			inputStream = httpUrlConnection.getInputStream();
			InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "UTF-8");
			BufferedReader bufferReader = new BufferedReader(inputStreamReader);
			String str = null;
			while ((str = bufferReader.readLine()) != null) {
				buffer.append(str);
			}
			String buffer2str = buffer.toString();
			// System.out.println("响应数据：" + buffer2str);
			jsonObject = JSONObject.parseObject(buffer2str);
			bufferReader.close();
			inputStreamReader.close();
			inputStream.close();
			inputStream = null;
			httpUrlConnection.disconnect();
		} catch (ConnectException ce) {
			System.out.println("Server connect time out!");
			throw new ConnectException();
			// ce.printStackTrace();
		} catch (IOException ioe) {
			System.out.println("ioexception request error");
			throw new IOException();
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("http request error!");
			throw new Exception();
		} finally {
			try {
				if (inputStream != null) {
					inputStream.close();
				}
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
		}
		return jsonObject;
	}

	/**
	 * 解密 解密过程： 1.构造密钥生成器 2.根据ecnodeRules规则初始化密钥生成器 3.产生密钥 4.创建和初始化密码器
	 * 5.将加密后的字符串反纺成byte[]数组 6.将加密内容解密
	 */
	public static String AESDncode(String encodeRules, String content) {
		// 初始化向量,必须16位
		String ivStr = "AESCBCPKCS5Paddi";
		try {
			// 1.构造密钥生成器，指定为AES算法,不区分大小写
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
			// 新增下面两行，处理 Linux 操作系统下随机数生成不一致的问题
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			secureRandom.setSeed(encodeRules.getBytes());
			keygen.init(128, secureRandom);
			// 3.产生原始对称密钥
			SecretKey original_key = keygen.generateKey();
			// 4.获得原始对称密钥的字节数组
			byte[] raw = original_key.getEncoded();
			// 5.根据字节数组生成AES密钥
			SecretKey key = new SecretKeySpec(raw, "AES");
			// 6.根据指定算法AES自成密码器
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			// 7.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密(Decrypt_mode)操作，第二个参数为使用的KEY
			//// 指定一个初始化向量 (Initialization vector，IV)， IV 必须是16位
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivStr.getBytes("UTF-8")));
			// 8.将加密并编码后的内容解码成字节数组
			byte[] byte_content = new BASE64Decoder().decodeBuffer(content);
			/*
			 * 解密
			 */
			byte[] byte_decode = cipher.doFinal(byte_content);
			String AES_decode = new String(byte_decode, "utf-8");
			return AES_decode;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		// 如果有错就返加null
		return null;
	}
}
