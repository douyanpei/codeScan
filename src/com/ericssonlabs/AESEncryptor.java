package com.ericssonlabs;


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AESEncryptor {
	/**
	 * 加密
	 * 
	 * @param content
	 *            需要加密的内容
	 * @param password
	 *            加密密码
	 * @return
	 */
 
    public static byte[] encrypt(String content, String password) throws Exception {
        if (password == null) {
            System.out.print("Key为空null");
            return null;
        }
        // 判断Key是否为16位
        if (password.length() != 16) {
            System.out.print("Key长度不是16位");
            return null;
        }
        byte[] raw = password.getBytes("utf-8");
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");//"算法/模式/补码方式"
        //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");//"算法/模式/补码方式"
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        return Base64.encodeBase64(cipher.doFinal(content.getBytes("utf-8")));
    }
	/**
	 * 解密
	 * 
	 * @param content
	 *            待解密内容
	 * @param password
	 *            解密密钥
	 * @return
	 */
	public static String decrypt(byte[] content, String password) {
		try {
			// 判断Key是否正确
			if (password == null) {
				System.out.print("Key为空null");
				return null;
			}
			// 判断Key是否为16位
			if (password.length() != 16) {
				System.out.print("Key长度不是16位");
				return null;
			}
			byte[] raw = password.getBytes("utf-8");
			SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			try {
				byte[] original = cipher.doFinal(Base64.decodeBase64(content));
				String originalString = new String(original, "utf-8");
				return originalString;
			} catch (Exception e) {
				System.out.println(e.toString());
				return null;
			}
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	public static void main(String[] args) {
		try {
			String aaa = "天津人民";
			String bbb = new String(encrypt(aaa, "DHFJUUDHST7SHDJF"));

//			byte[] bb = aaa.getBytes();
			
			//			Properties props = StringUtil.getProperties("connector.properties");
//			JSONObject node = new JSONObject();  
//				node.put("examCode", "WQN20170616002C");
//				node.put("mailCode", "268140100158");
//				node.put("recipientAddr", "大家都好");
//				node.put("district", "河东区");
//				node.put("recipientTel", "1850264199");
//				node.put("recipient", "小5");
//				node.put("requestBillCode", "20170616000006");
//			System.out.println(node.toString());
			System.out.println(bbb);
			
			// System.out.println("原文字节：");
			// byte[] b = xml.getBytes("UTF-8");
			// System.out.println(byte2HexStr(b));
//			String aaaa = new String(AESEncryptor.encrypt(node.toString(), Constants.AESKEY));
//			System.out.println(aaaa);
//			
//			String bbbb="+/rn8jvfHIKEUugPIg1f4S9Mfe0PgQhK9Gnm9KsVsWJ/tSTC503hBrB2kzfQbhjmAoVjS2NZQyUr56yDV5jFQi3G6qrSvhX55mq6Pd/59w5kHi7GahFv+N5Zv/I17t3sguexOUjFKM8TZOBygi1c1H3fei/o8LPa6jBV2iIRqfwcCdSuso7fP4kItidCGBNECSWhSlFm9m7d2bDYP/KaOw==";
//			System.out.println(bbbb); 
//			System.out.println(new String(AESEncryptor.decrypt(aaaa.getBytes(), Constants.AESKEY)));
//			 System.out.println(new String(AESEncryptor.decrypt(bbbb.getBytes(), Constants.AESKEY)));
			//System.out.println(new String(Base64.encodeBase64(AESEncryptor.encrypt(xml, "asiwu76ht95gd37h")), "UTF-8"));
//		} catch (JSONException e) {
//			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
