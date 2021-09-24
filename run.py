import subprocess
import os
import shutil

ARCHITECTURES = {
    'arm64': {
        'SDK': 'iphoneos',
    },
    'x86_64': {
        'SDK': 'iphonesimulator'
    }
}

PATCHES = {
    'build.rs': {
        'ORIGIN_PATH': 'quiche/src/build.rs',
        'PATCH_PATH': '../patches/diff/build.rs.diff',
    },
}

TLS_RS_FUNCTIONS_TO_REPLACE = [
    'TLS_method',
    'SSL_CTX_new',
    'SSL_CTX_free',
    'SSL_CTX_use_certificate_chain_file',
    'SSL_CTX_use_PrivateKey_file',
    'SSL_CTX_load_verify_locations',
    'SSL_CTX_set_default_verify_paths',
    'SSL_CTX_get_cert_store',
    'SSL_CTX_set_verify',
    'SSL_CTX_set_keylog_callback',
    'SSL_CTX_set_tlsext_ticket_keys',
    'SSL_CTX_set_alpn_protos',
    'SSL_CTX_set_alpn_select_cb',
    'SSL_CTX_set_early_data_enabled',
    'SSL_CTX_set_session_cache_mode',
    'SSL_CTX_sess_set_new_cb',
    'SSL_get_ex_new_index',
    'SSL_new',
    'SSL_get_error',
    'SSL_get_server_name',
    'SSL_set_accept_state',
    'SSL_set_connect_state',
    'SSL_get0_param',
    'SSL_set_ex_data',
    'SSL_get_ex_data',
    'SSL_get_current_cipher',
    'SSL_get_curve_id',
    'SSL_get_curve_name',
    'SSL_get_peer_signature_algorithm',
    'SSL_get_signature_algorithm_name',
    'SSL_set_session',
    'SSL_get_SSL_CTX',
    'SSL_get0_peer_certificates',
    'SSL_set_min_proto_version',
    'SSL_set_max_proto_version',
    'SSL_set_quiet_shutdown',
    'SSL_set_tlsext_host_name',
    'SSL_set_quic_transport_params',
    'SSL_set_options',
    'SSL_set_quic_method',
    'SSL_set_quic_use_legacy_codepoint',
    'SSL_set_quic_early_data_context',
    'SSL_get_peer_quic_transport_params',
    'SSL_get0_alpn_selected',
    'SSL_provide_quic_data',
    'SSL_process_quic_post_handshake',
    'SSL_reset_early_data_reject',
    'SSL_do_handshake',
    'SSL_quic_write_level',
    'SSL_session_reused',
    'SSL_in_init',
    'SSL_in_early_data',
    'SSL_clear',
    'SSL_free',
    'SSL_CIPHER_get_id',
    'SSL_SESSION_to_bytes',
    'SSL_SESSION_from_bytes',
    'SSL_SESSION_free',
    'X509_VERIFY_PARAM_set1_host',
    'X509_STORE_add_cert',
    'X509_free',
    'd2i_X509',
    'sk_num',
    'sk_value',
    'CRYPTO_BUFFER_len',
    'CRYPTO_BUFFER_data',
    'ERR_peek_error',
    'ERR_error_string_n'
]

RAND_RS_FUNCTIONS_TO_REPLACE = [
        'RAND_bytes'
]

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description="quiche ios builder")
    parser.add_argument("-v", "--ver", default="0.10.0", help="quiche version")
    parser.add_argument("-p", "--prefix", default="QUICHE", help="boringssl symbol prefix")
    parser.add_argument("-a", "--arch", default="arm64", help="architecture")
    return parser.parse_args()

def cleanup_mkdir(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    os.mkdir(path)

def checkout_quiche_repository(ver):
    print("try to clone quiche repository")
    subprocess.run(["git", "clone", "--recursive", "https://github.com/cloudflare/quiche"])
    print("done")
    os.chdir("quiche")
    print(f'try to checkout version: {ver}')
    subprocess.run(["git", "fetch"])
    subprocess.run(["git", "checkout", "-b", ver, f'refs/tags/{ver}'])
    print("done")
    os.chdir("..")

def replace_symbols(file, prefix, symbol):
    print(f'replace symbol:{symbol} in {file}')
    prefixed_symbol = f'{prefix}_{symbol}'
    subprocess.run(f'sed -i "" "s/{symbol}/{prefixed_symbol}/g" {file}', shell=True, env={'LC_ALL': 'C'})

def replace_fn_name(file, before, after):
    print(f'replace function:{before} in {after}')
    subprocess.run(f'sed -i "" "s/{before}/{after}/g" {file}', shell=True, env={'LC_ALL': 'C'})

def get_bitcode_option(arch):
    if arch == "arm64":
        return "-fembed-bitcode"
    else:
        return "-fembed-bitcode -target x86_64-apple-ios-simulator"


def build_boringssl(build_type, sdk, arch, prefix):
    print(f'try to build BoringSSL:{build_type}:{sdk}:{arch}')
    os.chdir("quiche/deps/boringssl/src")
    os.makedirs(f'build/{build_type}', exist_ok=True)
    os.chdir(f'build/{build_type}')
    command = f'cmake ../.. -DCMAKE_BUILD_TYPE={build_type} -DCMAKE_OSX_SYSROOT={sdk} -DCMAKE_OSX_ARCHITECTURES="{arch}"'
    option = get_bitcode_option(arch)
    command = command + f' -DCMAKE_ASM_FLAGS="{option}" -DCMAKE_C_FLAGS="{option}" -DCMAKE_CXX_FLAGS="{option}"'
    subprocess.run(command, shell=True)
    subprocess.run(["make", "-j", "4"])
    subprocess.run('go run ../../util/read_symbols.go ssl/libssl.a > ./symbols.txt', shell=True)
    subprocess.run('go run ../../util/read_symbols.go crypto/libcrypto.a >> ./symbols.txt', shell=True)

    command = command + f' -DBORINGSSL_PREFIX={prefix} -DBORINGSSL_PREFIX_SYMBOLS=symbols.txt'
    subprocess.run(command, shell=True)
    subprocess.run(["make", "-j", "4"])
    shutil.copyfile("ssl/libssl.a", "libssl.a")
    shutil.copyfile("crypto/libcrypto.a", "libcrypto.a")
    os.chdir("../../../../../..")

def patch_files():
    for key in PATCHES:
        print(f'try to patch {key}')
        patch = PATCHES[key]
        subprocess.run(f'patch -u {patch["ORIGIN_PATH"]} < {patch["PATCH_PATH"]}', shell=True)
        print("done")

def main(args):
    arch = args.arch
    if arch in ARCHITECTURES:
        setting = ARCHITECTURES[arch]
        sdk = setting['SDK']
        cleanup_mkdir(arch)
        os.chdir(arch)
        checkout_quiche_repository(args.ver)
        patch_files()
        #for build_type in ['Debug', 'RelWithDebInfo', 'Release', 'MinSizeRel']:
        for build_type in ['MinSizeRel']:
            build_boringssl(build_type, sdk, arch, args.prefix)
        os.chdir("quiche/src")
        for symbol in TLS_RS_FUNCTIONS_TO_REPLACE:
            replace_symbols("tls.rs", args.prefix, symbol)
        # SSL_freeを、{PREFIX}_SSL_freeにするようにreplaceすると
        # OPENSSL_freeが巻き添えを食って、OPEN{PREFIX}_SSL_freeになってしまうという問題があるのでそのフォロー
        replace_fn_name("tls.rs", f'OPEN{args.prefix}_SSL_free', f'{args.prefix}_OPENSSL_free')
        for symbol in RAND_RS_FUNCTIONS_TO_REPLACE:
            replace_symbols("rand.rs", args.prefix, symbol)
        os.chdir("../../..")
    else:
        print(f'architecture:"{arch}" not supported.')

if __name__ == "__main__":
    main(parse_args())

