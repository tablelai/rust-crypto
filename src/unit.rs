use aesl;
use jni::objects::{JObject, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use key::{EHT, IKEY};
use serialize::base64::{FromBase64, ToBase64, STANDARD};
use std::time::{SystemTime, UNIX_EPOCH};

#[no_mangle]
pub unsafe extern "C" fn Java_org_tests_Test_aes(
    env: JNIEnv,
    _jclass: JObject,
    data: JString,
) -> jstring {
    return Java_com_fcwc_pay_utils_AESUtil_aes(env, _jclass, data);
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_tests_Test_aesd(
    env: JNIEnv,
    _jclass: JObject,
    data: JString,
    de: i32,
) -> jstring {
    return Java_com_fcwc_pay_utils_AESUtil_aesd(env, _jclass, data, de);
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_tests_Test_unaes(
    env: JNIEnv,
    _jclass: JObject,
    data: JString,
) -> jstring {
    return Java_com_fcwc_pay_utils_AESUtil_unaes(env, _jclass, data);
}

#[no_mangle]
pub unsafe extern "C" fn Java_org_tests_Test_unaesd(
    env: JNIEnv,
    _jclass: JObject,
    data: JString,
    de: i32,
) -> jstring {
    return Java_com_fcwc_pay_utils_AESUtil_unaesd(env, _jclass, data, de);
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_fcwc_pay_utils_AESUtil_aes(
    env: JNIEnv,
    _jclass: JObject,
    data: JString,
) -> jstring {
    return Java_com_fcwc_pay_utils_AESUtil_aesd(env, _jclass, data, 0);
}

#[no_mangle]
pub extern "C" fn Java_com_fcwc_pay_utils_AESUtil_aesd(
    env: JNIEnv,
    _jclass: JObject,
    data: JString,
    de: i32,
) -> jstring {
    let ds: String = env.get_string(data).expect("参数错误——lib——en!").into();
    let ik = IKEY::new(de);
    let encrypted_data = aesl::encrypt(ds.as_bytes(), &ik.key, &ik.iv).ok().unwrap();
    let es = encrypted_data.to_base64(STANDARD);
    let output = env.new_string(es).unwrap();
    output.into_inner()
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_fcwc_pay_utils_AESUtil_unaes(
    env: JNIEnv,
    _jclass: JObject,
    data: JString,
) -> jstring {
    return Java_com_fcwc_pay_utils_AESUtil_unaesd(env, _jclass, data, 0);
}

#[no_mangle]
pub extern "C" fn Java_com_fcwc_pay_utils_AESUtil_unaesd(
    env: JNIEnv,
    _jclass: JObject,
    data: JString,
    de: i32,
) -> jstring {
    let t_n = timestamp_unix();
    if (EHT < t_n) {
        println!("授权已过期，请联系管理员");
        return env.new_string("666").unwrap().into_inner();
    }
    let ds: String = env.get_string(data).expect("参数错误——lib——un!").into();
    let ik = IKEY::new(de);
    let et = match ds.from_base64() {
        Ok(d) => d,
        Err(_e) => {
            println!("unbase64转换失败：{:?}", ds);
            return env.new_string(ds).unwrap().into_inner();
        }
    };
    let ss = match aesl::decrypt(&et, &ik.key, &ik.iv).ok() {
        Some(d) => d,
        None => {
            println!("解密失败：{:?}，密文：{:?}", et, ds);
            return env.new_string(ds).unwrap().into_inner();
        }
    };
    let rs = String::from_utf8(ss).unwrap();
    return env.new_string(rs).unwrap().into_inner();
}

fn timestamp() -> i64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let ms = since_the_epoch.as_secs() as i64 * 1000i64
        + (since_the_epoch.subsec_nanos() as f64 / 1_000_000.0) as i64;
    ms
}

fn timestamp_unix() -> i64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let ms = since_the_epoch.as_secs() as i64;
    ms
}
