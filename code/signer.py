import os.path
import sys
from fileutils import *
from rdpsign import main
from certchecker import *
import yaml
import argparse


def config_keys_check(config_rdp_sign):
    """
    Check whether RemoteAPP Signer sign config dict contains and only contains the correct keys
    :param config_rdp_sign: RDP sign config (from yaml config) dict
    :return: whether your rdp sign config dict contains and only contains the correct keys
    """
    allowed_config_keys = {"output": ["folder"], "sign": ["certificate", "key", "password"]}
    config_rdp_sign_keys = list(config_rdp_sign.keys())
    if set(config_rdp_sign_keys) != set(allowed_config_keys.keys()):
        print("[ERROR] RemoteAPPSign config file is invalid: extra or missing global config tags found")
        return False
    config_rdp_output = config_rdp_sign["output"]
    if set(config_rdp_output.keys()) != set(allowed_config_keys["output"]):
        print("[ERROR] RemoteAPPSign config file is invalid: extra or missing output config tags found")
        return False
    config_rdp_sign = config_rdp_sign["sign"]
    if set(config_rdp_sign.keys()) != set(allowed_config_keys["sign"]):
        print("[ERROR] RemoteAPPSign config file is invalid: extra or missing sign config tags found")
        return False
    return True


def config_output_check(config_rdp_sign, encoding):
    """
    Check whether RemoteAPP Signer sign output config is valid
    :param config_rdp_sign: RDP sign config (from yaml config) dict
    :param encoding: encoding format of RDP file (only supports UTF-8 and UTF-16-LE right now)
    :return: whether your rdp sign output config is valid
    """
    signed_rdp_output_folder = config_rdp_sign["output"]["folder"]
    if not os.path.exists(signed_rdp_output_folder) or not os.path.isdir(signed_rdp_output_folder):
        print("[WARNING] Signed RemoteAPPSign output folder: [%s] not found, trying to create" % signed_rdp_output_folder)
        os.mkdir(signed_rdp_output_folder)
        if not os.path.exists(signed_rdp_output_folder) or not os.path.isdir(signed_rdp_output_folder):
            print("[ERROR] Failed to create signed RemoteAPPSign output folder: [%s]" % signed_rdp_output_folder)
            return False
    try:
        output_write_check_path = os.path.join(signed_rdp_output_folder, "output.txt")
        if encoding == "utf-8":
            file_encoding = "utf-8"
        elif encoding == "utf-16":
            file_encoding = "utf-16-le"
        else:
            print("[ERROR] RDP file encoding must be either utf-8 or utf-16")
            return False
        with open(output_write_check_path, 'w', encoding=file_encoding) as wcw:
            wcw.write("test\n")
        with open(output_write_check_path, 'r', encoding=file_encoding) as wcr:
            check_content = wcr.readlines()[0].strip().replace("\r", "").replace("\n", "")
            if check_content != "test":
                print("[ERROR] Signed RemoteAPPSign output folder reading test failure")
                return False
        os.remove(output_write_check_path)
    except Exception as e:
        print("[ERROR] Signed RemoteAPPSign output folder writing&reading permission test failure")
        return False
    return True


def config_sign_check(config_rdp_sign):
    """
    Check whether RemoteAPP Signer sign config is valid
    :param config_rdp_sign: whether RemoteAPP Signer sign config is valid
    :return: whether RemoteAPP Signer sign config is valid
    """
    # config cert check
    rdp_sign_cert_path = config_rdp_sign["sign"]["certificate"]
    if not os.path.exists(rdp_sign_cert_path) or not os.path.isfile(rdp_sign_cert_path):
        print("[ERROR] RemoteAPPSign certificate file not found")
        return False
    if not is_ssl_certificate_from_file(rdp_sign_cert_path):
        print("[ERROR] RemoteAPPSign certificate file is invalid, requiring a X.509 certificate with Server Authentication "
              "Extension (OID: 1.3.6.1.5.5.7.3.1)")
        return False
    if check_ocsp_revocation_from_file(rdp_sign_cert_path):
        print("[ERROR] RemoteAPPSign certificate file is revoked according to OCSP checking results")
        return False
    if check_crl_revocation_from_file(rdp_sign_cert_path):
        print("[ERROR] RemoteAPPSign certificate file is revoked according to CRL checking results")
        return False
    if not check_secure_signature_algorithm_from_file(rdp_sign_cert_path):
        print("[ERROR] RemoteAPPSign certificate file is using an insecure signature hash algorithm, allowed: "
              "sha256WithRSAEncryption, sha384WithRSAEncryption, sha512WithRSAEncryption, ecdsa-with-SHA256, "
              "ecdsa-with-SHA384, ecdsa-with-SHA512")
        return False
    # config key check
    rdp_sign_key_path = config_rdp_sign["sign"]["key"]
    rdp_sign_password = config_rdp_sign["sign"]["password"]
    if not os.path.exists(rdp_sign_key_path) or not os.path.isfile(rdp_sign_key_path):
        print("[ERROR] RemoteAPPSign key file not found")
        return False
    if not verify_key_match_from_file(rdp_sign_cert_path, rdp_sign_key_path, rdp_sign_password):
        print("[ERROR] RemoteAPPSign certificate and key do not match")
        return False
    return True


def config_file_check(rdp_files_path, mode, encoding):
    """
    Check whether input unsigned rdp file is valid
    :param rdp_files_path: all unsigned rdp file path
    :param mode: signing file mode (single: one RDP file a time, multi: one folder containing multiple RDP files a time)
    :param encoding: encoding format of RDP file (only supports UTF-8 and UTF-16-LE right now)
    :return: whether input unsigned rdp file is valid
    """
    if encoding == "utf-8":
        file_encoding = "utf-8-sig"
    elif encoding == "utf-16":
        file_encoding = "utf-16-le"
    else:
        print("[ERROR] RDP file encoding must be either utf-8 or utf-16")
        return False
    if mode == "single":
        if not isinstance(rdp_files_path, str):
            print(f"[ERROR] RemoteAPPSign target file path {rdp_files_path} for single signing mode is not a string")
            return False
        if not os.path.exists(rdp_files_path) or not os.path.isfile(rdp_files_path):
            print(f"[ERROR] RemoteAPPSign target file {rdp_files_path} not found")
            return False
        try:
            with open(rdp_files_path, 'r', encoding=file_encoding) as rdp_rd:
                rdp_rd.read()
        except Exception as e:
            print(e)
            print(f"[ERROR] RemoteAPPSign target file {rdp_files_path} is not UTF-8 encoded")
            return False
        return True
    elif mode == "multi":
        if not isinstance(rdp_files_path, str):
            print(f"[ERROR] RemoteAPPSign target file path {rdp_files_path} for multi signing mode is not a list nor a string")
            return False
        rdp_files_path = list_folder_files(rdp_files_path, included_ext=[".rdp"])
        for rdp_file_path in rdp_files_path:
            if not config_file_check(rdp_file_path, "single", encoding):
                return False
        return True
    else:
        return False


def sign_rdp_file(unsigned_input_path, signed_output_path, cert_sign, key_sign, key_password, sign_mode, encoding):
    """
    Core function for signing rdp file
    :param unsigned_input_path: unsigned rdp file path (file path for single mode, folder path for multi mode)
    :param signed_output_path: output path for signed rdp files
    :param cert_sign: SSL certificate for signing rdp file
    :param key_sign: SSL private key for signing rdp file
    :param key_password: key phase for decrypting SSL private key
    :param sign_mode: RDP signing mode (single: one RDP file a time, multi: one folder containing multiple RDP files a time)
    :param encoding: encoding format of RDP file (only supports UTF-8 and UTF-16-LE right now)
    :return: whether provided unsigned rdp file is successfully signed
    """
    if key_password is not None and key_password:
        raise Exception("[ERROR] RemoteAPPSigner does not support private key password currently")
    if sign_mode == "single":
        unsigned_input_path = unsigned_input_path.strip().replace("\\", "/").replace("//", "/")
        unsigned_input_filename = unsigned_input_path.split("/")[-1]
        if "/" in unsigned_input_path:
            unsigned_output_path = os.path.join(signed_output_path, unsigned_input_filename)
        else:
            unsigned_output_path = os.path.join(signed_output_path, unsigned_input_path)
        rdp_sign_argv = [os.path.abspath(__file__), unsigned_input_path, unsigned_output_path, cert_sign, "-k", key_sign,
                         "-e", encoding]
        main(rdp_sign_argv)
        print(f"[INFO] RemoteAPPSigner has successfully signed {unsigned_input_filename}")
        return True
    elif sign_mode == "multi":
        unsigned_input_filepath = list_folder_files(unsigned_input_path, included_ext=[".rdp"])
        if not unsigned_input_filepath:
            print(f"[ERROR] No .rdp file found in such folder to sign: {unsigned_input_filepath}")
            return False
        for i in range(len(unsigned_input_filepath)):
            unsigned_input_filepath[i] = unsigned_input_filepath[i].strip().replace("\\", "/").replace("//", "/")
            if not sign_rdp_file(unsigned_input_filepath[i], signed_output_path, cert_sign, key_sign, key_password, "single", encoding):
                return False
        return True
    else:
        return False


def sign_list_dispatch(sign_list_path):
    """
    Analysing sign list config (.yaml) file and convert it to get all unsigned rdp file path
    :param sign_list_path: sign list config yaml file path
    :return: all unsigned rdp file path
    """
    allowed_sign_list_keys = ["file", "folder"]
    unsigned_file_list = []
    try:
        with open(sign_list_path, 'r', encoding='utf-8') as slr:
            sign_list = yaml.safe_load(slr)
            if set(sign_list.keys()) != set(allowed_sign_list_keys):
                print("[ERROR] Sign list contains invalid keys, allowed: %s" % ", ".join(allowed_sign_list_keys))
                return []
            single_file_sign_list = sign_list["file"]
            for single_file_sign in single_file_sign_list:
                if not os.path.exists(single_file_sign) or not os.path.isfile(single_file_sign):
                    print(f"[ERROR] RemoteAPPSign target file {single_file_sign} not found")
                    return []
                unsigned_file_list.append(single_file_sign)
            multi_file_sign_list = sign_list["folder"]
            for multi_file_sign in multi_file_sign_list:
                if not os.path.exists(multi_file_sign) or not os.path.isdir(multi_file_sign):
                    print(f"[ERROR] RemoteAPPSign target folder {multi_file_sign} not found")
                    return []
                unsigned_file_list.extend(list_folder_files(multi_file_sign, included_ext=[".rdp"]))
            return unsigned_file_list
    except Exception:
        return []


def sign_preprocess(argv) -> bool:
    """
    Preprocessing argv input through command line
    :param argv: signing options for RemoteAPPSigner
    :return: whether signing for all RDP files is successful
    """
    # parser definition
    parser = argparse.ArgumentParser('signer')
    parser.add_argument("-s", "--single", action="store_true", help="Simply sign a single single rdp file")
    parser.add_argument("-m", "--multi", action="store_true", help="Sign multiple rdp files")
    parser.add_argument("-c", "--config", type=str, default='config.yml', help="Specify rdp sign config file")
    parser.add_argument("-i", "--infile", type=str, default='signlist.yml', help="rdp file to be signed")
    parser.add_argument("-e", "--encoding", type=str, default='utf-8', help="rdp file encoding format")
    # parser spliter
    args = parser.parse_args(argv[1:])
    # sign mode (single/multi)
    single_sign_mode = bool(args.single)
    multi_sign_mode = bool(args.multi)
    if single_sign_mode:
        sign_mode = "single"
    else:
        if multi_sign_mode:
            sign_mode = "multi"
        else:
            sign_mode = "single"
    # config yaml reader & checker
    config_yaml_path = str(args.config)
    if not os.path.exists(config_yaml_path) or not os.path.isfile(config_yaml_path):
        print("[ERROR] RemoteAPPSign config file not found")
        return False
    with open(config_yaml_path, 'r', encoding="utf-8") as cfr:
        config_rdp_sign = yaml.safe_load(cfr)
    # unsigned rdp path
    unsigned_rdp_path = str(args.infile)
    # encoding format
    unsigned_rdp_encoding_format = str(args.encoding)
    if unsigned_rdp_path.endswith(".yml"):
        unsigned_rdp_files_path = sign_list_dispatch(unsigned_rdp_path)
        for unsigned_rdp_file_path in unsigned_rdp_files_path:
            sign_argv = [os.path.abspath(__file__), "-i", unsigned_rdp_file_path, "-s", "-c", config_yaml_path, "-e", unsigned_rdp_encoding_format]
            if not sign_preprocess(sign_argv):
                return False
        return True
    if (not config_keys_check(config_rdp_sign) or not config_output_check(config_rdp_sign, unsigned_rdp_encoding_format)
            or not config_sign_check(config_rdp_sign) or not config_file_check(unsigned_rdp_path, sign_mode, unsigned_rdp_encoding_format)):
        return False
    signed_output_path = config_rdp_sign["output"]["folder"]
    cert_sign = config_rdp_sign["sign"]["certificate"]
    key_sign = config_rdp_sign["sign"]["key"]
    key_password = config_rdp_sign["sign"]["password"]
    return sign_rdp_file(unsigned_rdp_path, signed_output_path, cert_sign, key_sign, key_password, sign_mode, unsigned_rdp_encoding_format)



if __name__ == "__main__":
    if sign_preprocess(sys.argv):
        print("[INFO] RemoteAPPSigner has successfully signed all .rdp files")
    else:
        print("[ERROR] RemoteAPPSigner has not successfully signed all .rdp files")
    input("[INFO] Press any key to exit\n")
