use std::ffi::{CStr, CString};

use aesl;
use jni::objects::{JObject, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use key;
use rand::{OsRng, Rng};
use serialize::base64::{FromBase64, ToBase64, STANDARD};

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
pub unsafe extern "C" fn Java_com_fcwc_pay_utils_AESUtil_aesd(
    env: JNIEnv,
    _jclass: JObject,
    data: JString,
    de: i32,
) -> jstring {
    let ds = CString::from(CStr::from_ptr(env.get_string(data).unwrap().as_ptr()));
    if de == 1 {
        println!("原文： {:?}", ds);
    }

    let encrypted_data = aesl::encrypt(ds.as_bytes(), &key::KEY, &key::IV)
        .ok()
        .unwrap();
    if de == 1 {
        println!("密文： {:?}", &encrypted_data[..]);
    }

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
pub unsafe extern "C" fn Java_com_fcwc_pay_utils_AESUtil_unaesd(
    env: JNIEnv,
    _jclass: JObject,
    data: JString,
    de: i32,
) -> jstring {
    let ds = CString::from(CStr::from_ptr(env.get_string(data).unwrap().as_ptr()));
    if de == 1 {
        println!("密文： {:?}", ds);
    }
    let et = ds.as_bytes().from_base64().unwrap();
    let ss = aesl::decrypt(&et, &key::KEY, &key::IV).ok().unwrap();
    if de == 1 {
        println!("原文： {:?}", ss);
    }
    let output = env.new_string(String::from_utf8_unchecked(ss)).unwrap();
    output.into_inner()
}
