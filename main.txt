use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce as AesNonce};
// hmac::Mac 트레이트를 가져와서 HMAC 관련 함수 사용 가능하게 설정
use hmac::{Hmac, Mac};
use pqcrypto_kyber::kyber768::*;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{Digest as Sha3Digest, Sha3_512};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

// =====================================================================
// [1] 제로 트러스트 메모리 관리 (Zero Trust & Memory Safety)
// =====================================================================

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSeed(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKey(pub [u8; 32]);

impl fmt::Debug for MasterSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MasterSeed([SECURE_RAM_ONLY; 32])")
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionKey([SECURE_RAM_ONLY; 32])")
    }
}

// =====================================================================
// [2] 동적 익명 토큰 (Token_ID) 생성기
// =====================================================================
pub fn generate_token_id(client_id: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(client_id);
    hasher.update(nonce);
    let result = hasher.finalize();
    let mut token = [0u8; 32];
    token.copy_from_slice(&result);
    token
}

// =====================================================================
// [3] XorNet KDF v3.0 엔진
// =====================================================================

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

pub fn xornet_kdf_v3(seed: &MasterSeed, nonce: &[u8]) -> SessionKey {
    let mut hasher1 = Sha3_512::new();
    hasher1.update(&seed.0);
    hasher1.update(nonce);
    hasher1.update(&[0x01]);
    let x1 = hasher1.finalize();

    let mut hasher2 = Sha3_512::new();
    hasher2.update(&seed.0);
    hasher2.update(nonce);
    hasher2.update(&[0x02]);
    let x2 = hasher2.finalize();

    let mut hasher3 = Sha3_512::new();
    hasher3.update(&seed.0);
    hasher3.update(nonce);
    hasher3.update(&[0x03]);
    let x3 = hasher3.finalize();

    let mut derived_key = [0u8; 32];
    for i in 0..32 {
        let mix = x1[i] ^ x2[i + 16] ^ x3[i + 32];
        let rotated = (mix << 3) | (mix >> 5);
        derived_key[i] = SBOX[rotated as usize];
    }

    SessionKey(derived_key)
}

// =====================================================================
// [4] 동적 키 래칫 (Key Ratcheting)
// =====================================================================
pub fn key_ratchet(old_seed: &mut MasterSeed, session_nonce: &[u8]) -> MasterSeed {
    let mut hasher = Sha3_512::new();
    hasher.update(&old_seed.0);
    hasher.update(session_nonce);
    let result = hasher.finalize();

    let mut new_seed_bytes = [0u8; 32];
    new_seed_bytes.copy_from_slice(&result[0..32]);

    old_seed.zeroize();
    MasterSeed(new_seed_bytes)
}

// =====================================================================
// [5] TPM 1.2 보완 호환 모드 (Dual Wrapping)
// =====================================================================
pub struct Tpm12DualWrapper {
    aes_key: [u8; 32],
    hmac_key: [u8; 32],
}

impl Tpm12DualWrapper {
    pub fn new(aes_key: &[u8; 32], hmac_key: &[u8; 32]) -> Self {
        Self {
            aes_key: *aes_key,
            hmac_key: *hmac_key,
        }
    }

    pub fn seal(&self, data: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let cipher = Aes256Gcm::new(&self.aes_key.into());
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = AesNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data).expect("AES Encrypt Failure");
        
        let mut sealed_payload = Vec::new();
        sealed_payload.extend_from_slice(&nonce_bytes);
        sealed_payload.extend_from_slice(&ciphertext);

        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&self.hmac_key).expect("HMAC Key Failure");
        mac.update(&sealed_payload);
        let hmac_tag = mac.finalize().into_bytes();
        let mut tag_array = [0u8; 32];
        tag_array.copy_from_slice(&hmac_tag);

        (sealed_payload, tag_array)
    }

    pub fn unseal(&self, sealed_payload: &[u8], expected_tag: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&self.hmac_key).expect("HMAC Key Failure");
        mac.update(sealed_payload);
        if mac.verify_slice(expected_tag).is_err() {
            return Err("HMAC 무결성 검증 실패: 데이터가 변조되었습니다.");
        }

        if sealed_payload.len() < 12 {
            return Err("페이로드 길이가 너무 짧습니다.");
        }
        let (nonce_bytes, ciphertext) = sealed_payload.split_at(12);
        let cipher = Aes256Gcm::new(&self.aes_key.into());
        let nonce = AesNonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, ciphertext).map_err(|_| "AES 복호화 실패")
    }
}

// =====================================================================
// [6] 메인 실행 시나리오
// =====================================================================
fn main() {
    println!("============================================================");
    println!("      XorNet 4.5 양자내성 하이브리드 보안 프로토콜 가동      ");
    println!("============================================================\n");

    // [Step 1] 키쌍 생성
    println!("[Step 1] 서버 ML-KEM-768 (Kyber768) 키쌍 생성 중...");
    let (server_pk, server_sk) = keypair();
    println!(" -> 서버 공개키 생성 완료. (크기: {} bytes)", server_pk.as_bytes().len());

    // [Step 2] 동적 익명 토큰 및 캡슐화
    println!("\n[Step 2] 클라이언트 동적 익명 토큰(Token_ID) 및 캡슐화 수행");
    let client_id = b"user_endpoint_x992";
    let mut reg_nonce = [0u8; 16];
    OsRng.fill_bytes(&mut reg_nonce);
    
    let token_id = generate_token_id(client_id, &reg_nonce);
    println!(" -> 평문 ID 전송 차단! 동적 익명 Token_ID: {:x?}", &token_id[0..8]);

    let (client_shared_secret, ciphertext) = encapsulate(&server_pk);
    let mut client_master_seed = MasterSeed(client_shared_secret.as_bytes().try_into().unwrap());
    println!(" -> ML-KEM-768 캡슐화 완료. 서버로 암호문 전송 (크기: {} bytes)", ciphertext.as_bytes().len());

    // [Step 3] 서버 캡슐 해제
    println!("\n[Step 3] 서버 캡슐화 해제(Decapsulation) 및 1단계 수립");
    let server_shared_secret = decapsulate(&ciphertext, &server_sk);
    let mut server_master_seed = MasterSeed(server_shared_secret.as_bytes().try_into().unwrap());
    
    let mut db_hasher = Sha256::new();
    db_hasher.update(&server_master_seed.0);
    let db_hash_record = db_hasher.finalize();
    println!(" -> 서버 Secure RAM 시드 복원 완료.");
    println!(" -> 서버 DB 저장용 단방향 해시 기록: {:x?}...", &db_hash_record[0..8]);

    // [Step 4] KDF v3.0 세션 키 도출 및 암호화 통신
    println!("\n[Step 4] XorNet KDF v3.0 세션 키 도출 및 AES-256-GCM 통신");
    let mut session_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut session_nonce);

    let client_session_key = xornet_kdf_v3(&client_master_seed, &session_nonce);
    let server_session_key = xornet_kdf_v3(&server_master_seed, &session_nonce);

    assert_eq!(client_session_key.0, server_session_key.0, "KDF 도출 키 불일치!");
    println!(" -> KDF v3.0 세션 키 완벽 일치!");

    let secret_payload = b"Top Secret: Zero Trust PQC Endpoint Data Payload!";
    let cipher = Aes256Gcm::new(&client_session_key.0.into());
    let mut aes_nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut aes_nonce_bytes);
    let aes_nonce = AesNonce::from_slice(&aes_nonce_bytes);

    let encrypted_data = cipher.encrypt(aes_nonce, secret_payload.as_slice()).expect("암호화 실패");
    println!(" -> 암호화된 전송 페이로드: {:x?}... (총 {} bytes)", &encrypted_data[0..10], encrypted_data.len());

    let server_cipher = Aes256Gcm::new(&server_session_key.0.into());
    let decrypted_data = server_cipher.decrypt(aes_nonce, encrypted_data.as_slice()).expect("복호화 실패");
    println!(" -> 서버 복호화 성공! 수신 메시지: \"{}\"", String::from_utf8_lossy(&decrypted_data));

    // [Step 5] 키 래칫
    println!("\n[Step 5] 동적 키 래칫(Key Ratcheting) 수행");
    let mut ratchet_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut ratchet_nonce);

    println!(" -> 래칫 전 클라이언트 시드: {:x?}", &client_master_seed.0[0..4]);
    client_master_seed = key_ratchet(&mut client_master_seed, &ratchet_nonce);
    server_master_seed = key_ratchet(&mut server_master_seed, &ratchet_nonce);
    println!(" -> 래칫 후 클라이언트 시드: {:x?}", &client_master_seed.0[0..4]);
    assert_eq!(client_master_seed.0, server_master_seed.0);
    println!(" -> 과거 시드 Zeroize 완료!");

    // [Step 6] TPM 1.2 보완 모드
    println!("\n[Step 6] TPM 1.2 보완 호환 모드 (HMAC + AES 이중 래핑)");
    let wrapper_aes = [0x11u8; 32];
    let wrapper_hmac = [0x22u8; 32];
    let tpm_wrapper = Tpm12DualWrapper::new(&wrapper_aes, &wrapper_hmac);

    let sensitive_data = b"Hardware Sealing Target Key Data";
    let (sealed, tag) = tpm_wrapper.seal(sensitive_data);
    println!(" -> 씰링 완료. HMAC 태그: {:x?}", &tag[0..8]);

    match tpm_wrapper.unseal(&sealed, &tag) {
        Ok(unsealed) => println!(" -> 씰링 해제 성공! 데이터: \"{}\"", String::from_utf8_lossy(&unsealed)),
        Err(e) => println!(" -> 씰링 해제 실패: {}", e),
    }

    println!("\n============================================================");
    println!("            XorNet 4.5 프로토콜 검증 성공 및 종료            ");
    println!("============================================================");
}