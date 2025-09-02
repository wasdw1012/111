import os
import sys
import subprocess
import secrets
import glob
import random
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pyasn1.type import univ, namedtype, char
from pyasn1.codec.der import encoder, decoder
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding



# 国家数据字典
COUNTRY_DATA = {
    # 非洲
    'CF': {'alpha3': 'CAF', 'full_name': 'Central African Republic', 'adjective': 'Central African'},
    'TD': {'alpha3': 'TCD', 'full_name': 'Chad', 'adjective': 'Chadian'},
    'KM': {'alpha3': 'COM', 'full_name': 'Comoros', 'adjective': 'Comorian'},
    'DJ': {'alpha3': 'DJI', 'full_name': 'Djibouti', 'adjective': 'Djiboutian'},
    'GQ': {'alpha3': 'GNQ', 'full_name': 'Equatorial Guinea', 'adjective': 'Equatorial Guinean'},
    'ER': {'alpha3': 'ERI', 'full_name': 'Eritrea', 'adjective': 'Eritrean'},
    'GM': {'alpha3': 'GMB', 'full_name': 'Gambia', 'adjective': 'Gambian'},
    'GW': {'alpha3': 'GNB', 'full_name': 'Guinea-Bissau', 'adjective': 'Bissau-Guinean'},
    'LR': {'alpha3': 'LBR', 'full_name': 'Liberia', 'adjective': 'Liberian'},
    'MW': {'alpha3': 'MWI', 'full_name': 'Malawi', 'adjective': 'Malawian'},
    'ML': {'alpha3': 'MLI', 'full_name': 'Mali', 'adjective': 'Malian'},
    'MR': {'alpha3': 'MRT', 'full_name': 'Mauritania', 'adjective': 'Mauritanian'},
    'NE': {'alpha3': 'NER', 'full_name': 'Niger', 'adjective': 'Nigerien'},
    'ST': {'alpha3': 'STP', 'full_name': 'Sao Tome and Principe', 'adjective': 'Sao Tomean'},
    'SL': {'alpha3': 'SLE', 'full_name': 'Sierra Leone', 'adjective': 'Sierra Leonean'},
    'SO': {'alpha3': 'SOM', 'full_name': 'Somalia', 'adjective': 'Somali'},
    'SS': {'alpha3': 'SSD', 'full_name': 'South Sudan', 'adjective': 'South Sudanese'},
    
    # 亚洲
    'AF': {'alpha3': 'AFG', 'full_name': 'Afghanistan', 'adjective': 'Afghan'},
    'BT': {'alpha3': 'BTN', 'full_name': 'Bhutan', 'adjective': 'Bhutanese'},
    'KH': {'alpha3': 'KHM', 'full_name': 'Cambodia', 'adjective': 'Cambodian'},
    'LA': {'alpha3': 'LAO', 'full_name': 'Laos', 'adjective': 'Lao'},
    'MV': {'alpha3': 'MDV', 'full_name': 'Maldives', 'adjective': 'Maldivian'},
    'MM': {'alpha3': 'MMR', 'full_name': 'Myanmar', 'adjective': 'Burmese'},
    'KP': {'alpha3': 'PRK', 'full_name': "Korea, Democratic People's Republic of", 'adjective': 'North Korean'},
    'LK': {'alpha3': 'LKA', 'full_name': 'Sri Lanka', 'adjective': 'Sri Lankan'},
    'TJ': {'alpha3': 'TJK', 'full_name': 'Tajikistan', 'adjective': 'Tajik'},
    'TM': {'alpha3': 'TKM', 'full_name': 'Turkmenistan', 'adjective': 'Turkmen'},
    'JP': {'alpha3': 'JPN', 'full_name': 'Japan', 'adjective': 'Japanese'},
    'AE': {'alpha3': 'ARE', 'full_name': 'United Arab Emirates', 'adjective': 'Emirati'},
    'CN': {'alpha3': 'CHN', 'full_name': 'China', 'adjective': 'Chinese'},
    
    # 欧洲
    'AD': {'alpha3': 'AND', 'full_name': 'Andorra', 'adjective': 'Andorran'},
    'XK': {'alpha3': 'XKX', 'full_name': 'Kosovo', 'adjective': 'Kosovar'},
    'LI': {'alpha3': 'LIE', 'full_name': 'Liechtenstein', 'adjective': 'Liechtenstein'},
    'ME': {'alpha3': 'MNE', 'full_name': 'Montenegro', 'adjective': 'Montenegrin'},
    'MK': {'alpha3': 'MKD', 'full_name': 'North Macedonia', 'adjective': 'Macedonian'},
    'VA': {'alpha3': 'VAT', 'full_name': 'Holy See (Vatican City State)', 'adjective': 'Vatican'},

    # 美洲
    'AG': {'alpha3': 'ATG', 'full_name': 'Antigua and Barbuda', 'adjective': 'Antiguan and Barbudan'},
    'BS': {'alpha3': 'BHS', 'full_name': 'Bahamas', 'adjective': 'Bahamian'},
    'BB': {'alpha3': 'BRB', 'full_name': 'Barbados', 'adjective': 'Barbadian'},
    'BO': {'alpha3': 'BOL', 'full_name': 'Bolivia', 'adjective': 'Bolivian'},
    'DM': {'alpha3': 'DMA', 'full_name': 'Dominica', 'adjective': 'Dominican'},
    'DO': {'alpha3': 'DOM', 'full_name': 'Dominican Republic', 'adjective': 'Dominican'},
    'SV': {'alpha3': 'SLV', 'full_name': 'El Salvador', 'adjective': 'Salvadoran'},
    'GD': {'alpha3': 'GRD', 'full_name': 'Grenada', 'adjective': 'Grenadian'},
    'GT': {'alpha3': 'GTM', 'full_name': 'Guatemala', 'adjective': 'Guatemalan'},
    'GY': {'alpha3': 'GUY', 'full_name': 'Guyana', 'adjective': 'Guyanese'},
    'HT': {'alpha3': 'HTI', 'full_name': 'Haiti', 'adjective': 'Haitian'},
    'HN': {'alpha3': 'HND', 'full_name': 'Honduras', 'adjective': 'Honduran'},
    'NI': {'alpha3': 'NIC', 'full_name': 'Nicaragua', 'adjective': 'Nicaraguan'},
    'PY': {'alpha3': 'PRY', 'full_name': 'Paraguay', 'adjective': 'Paraguayan'},
    'LC': {'alpha3': 'LCA', 'full_name': 'Saint Lucia', 'adjective': 'Saint Lucian'},
    'VC': {'alpha3': 'VCT', 'full_name': 'Saint Vincent and the Grenadines', 'adjective': 'Vincentian'},
    'SR': {'alpha3': 'SUR', 'full_name': 'Suriname', 'adjective': 'Surinamese'},
    'TT': {'alpha3': 'TTO', 'full_name': 'Trinidad and Tobago', 'adjective': 'Trinidadian and Tobagonian'},
    'UY': {'alpha3': 'URY', 'full_name': 'Uruguay', 'adjective': 'Uruguayan'},
    'VE': {'alpha3': 'VEN', 'full_name': 'Venezuela', 'adjective': 'Venezuelan'},

    # 大洋洲
    'FJ': {'alpha3': 'FJI', 'full_name': 'Fiji', 'adjective': 'Fijian'},
    'KI': {'alpha3': 'KIR', 'full_name': 'Kiribati', 'adjective': 'I-Kiribati'},
    'MH': {'alpha3': 'MHL', 'full_name': 'Marshall Islands', 'adjective': 'Marshallese'},
    'FM': {'alpha3': 'FSM', 'full_name': 'Micronesia, Federated States of', 'adjective': 'Micronesian'},
    'NR': {'alpha3': 'NRU', 'full_name': 'Nauru', 'adjective': 'Nauruan'},
    'PW': {'alpha3': 'PLW', 'full_name': 'Palau', 'adjective': 'Palauan'},
    'PG': {'alpha3': 'PNG', 'full_name': 'Papua New Guinea', 'adjective': 'Papua New Guinean'},
    'WS': {'alpha3': 'WSM', 'full_name': 'Samoa', 'adjective': 'Samoan'},
    'SB': {'alpha3': 'SLB', 'full_name': 'Solomon Islands', 'adjective': 'Solomon Islander'},
    'TO': {'alpha3': 'TON', 'full_name': 'Tonga', 'adjective': 'Tongan'},
    'TV': {'alpha3': 'TUV', 'full_name': 'Tuvalu', 'adjective': 'Tuvaluan'},
}


COUNTRY_FULL_NAMES = {
    'CF': 'Central African Republic', 'TD': 'Chad', 'KM': 'Comoros', 'DJ': 'Djibouti', 
    'GQ': 'Equatorial Guinea', 'ER': 'Eritrea', 'GM': 'Gambia', 'GW': 'Guinea-Bissau', 
    'LR': 'Liberia', 'MW': 'Malawi', 'ML': 'Mali', 'MR': 'Mauritania', 'NE': 'Niger', 
    'ST': 'Sao Tome and Principe', 'SL': 'Sierra Leone', 'SO': 'Somalia', 'SS': 'South Sudan',
    'AF': 'Afghanistan', 'BT': 'Bhutan', 'KH': 'Cambodia', 'LA': 'Laos', 'MV': 'Maldives',
    'MM': 'Myanmar', 'KP': "Korea, Democratic People's Republic of", 'LK': 'Sri Lanka', 
    'TJ': 'Tajikistan', 'TM': 'Turkmenistan', 'JP': 'Japan', 'AE': 'United Arab Emirates', 
    'CN': 'China', 'AD': 'Andorra', 'XK': 'Kosovo', 'LI': 'Liechtenstein', 'ME': 'Montenegro', 
    'MK': 'North Macedonia', 'VA': 'Holy See (Vatican City State)', 'AG': 'Antigua and Barbuda', 
    'BS': 'Bahamas', 'BB': 'Barbados', 'BO': 'Bolivia, Plurinational State of', 'DM': 'Dominica', 
    'DO': 'Dominican Republic', 'SV': 'El Salvador', 'GD': 'Grenada', 'GT': 'Guatemala', 
    'GY': 'Guyana', 'HT': 'Haiti', 'HN': 'Honduras', 'NI': 'Nicaragua', 'PY': 'Paraguay', 
    'LC': 'Saint Lucia', 'VC': 'Saint Vincent and the Grenadines', 'SR': 'Suriname', 
    'TT': 'Trinidad and Tobago', 'UY': 'Uruguay', 'VE': 'Venezuela, Bolivarian Republic of',
    'FJ': 'Fiji', 'KI': 'Kiribati', 'MH': 'Marshall Islands', 'FM': 'Micronesia, Federated States of', 
    'NR': 'Nauru', 'PW': 'Palau', 'PG': 'Papua New Guinea', 'WS': 'Samoa', 
    'SB': 'Solomon Islands', 'TO': 'Tonga', 'TV': 'Tuvalu',
}


AGENCY_ACRONYMS = {
    # 非洲
    'CF': 'MOI',   # Central African Republic: Ministry of Interior
    'TD': 'MFA',   # Chad: Ministry of Foreign Affairs
    'KM': 'MOI',   # Comoros: Ministry of Interior
    'DJ': 'MOI',   # Djibouti: Ministry of Interior
    'GQ': 'MFA',   # Equatorial Guinea: Ministry of Foreign Affairs
    'ER': 'DIN',   # Eritrea: Department of Immigration and Nationality
    'GM': 'GID',   # Gambia: Gambia Immigration Department
    'GW': 'MAI',   # Guinea-Bissau: Ministry of Internal Administration
    'LR': 'MFA',   # Liberia: Ministry of Foreign Affairs
    'MW': 'DICS',  # Malawi: Department of Immigration and Citizenship Services
    'ML': 'MSPC',  # Mali: Ministry of Security and Civil Protection
    'MR': 'MOI',   # Mauritania: Ministry of Interior
    'NE': 'MOI',   # Niger: Ministry of Interior
    'ST': 'MFA',   # Sao Tome and Principe: Ministry of Foreign Affairs
    'SL': 'SLID',  # Sierra Leone: Sierra Leone Immigration Department
    'SO': 'IND',   # Somalia: Immigration and Naturalization Directorate
    'SS': 'DNPI',  # South Sudan: Directorate of Nationality, Passports and Immigration
    
    # 亚洲
    'AF': 'MOIA',  # Afghanistan: Ministry of Interior Affairs
    'BT': 'MFA',   # Bhutan: Ministry of Foreign Affairs
    'KH': 'MOI',   # Cambodia: Ministry of Interior
    'LA': 'MFA',   # Laos: Ministry of Foreign Affairs
    'MV': 'MVI',   # Maldives: Maldives Immigration
    'MM': 'MIP',   # Myanmar: Ministry of Immigration and Population
    'KP': 'MFA',   # North Korea: Ministry of Foreign Affairs
    'LK': 'DIE',   # Sri Lanka: Department of Immigration and Emigration
    'TJ': 'MFA',   # Tajikistan: Ministry of Foreign Affairs
    'TM': 'SMS',   # Turkmenistan: State Migration Service
    'JP': 'MOFA',  # Japan: Ministry of Foreign Affairs
    'AE': 'ICA',   # UAE: Federal Authority for Identity and Citizenship
    'CN': 'NIA',   # China: National Immigration Administration
    
    # 欧洲
    'AD': 'MFA',   # Andorra: Ministry of Foreign Affairs
    'XK': 'MIA',   # Kosovo: Ministry of Internal Affairs
    'LI': 'APA',   # Liechtenstein: Immigration and Passport Office
    'ME': 'MUP',   # Montenegro: Ministry of Internal Affairs
    'MK': 'MVR',   # North Macedonia: Ministry of Internal Affairs
    'VA': 'GVCS',  # Vatican City: Governorate of Vatican City State
    
    # 美洲
    'AG': 'PO',    # Antigua and Barbuda: Passport Office
    'BS': 'PO',    # Bahamas: Passport Office
    'BB': 'BID',   # Barbados: Immigration Department
    'BO': 'DIGEMIG', # Bolivia: Dirección General de Migración
    'DM': 'MNS',   # Dominica: Ministry of National Security
    'DO': 'DGP',   # Dominican Republic: Dirección General de Pasaportes
    'SV': 'DGME',  # El Salvador: Dirección General de Migración y Extranjería
    'GD': 'IPD',   # Grenada: Immigration and Passport Department
    'GT': 'IGM',   # Guatemala: Instituto Guatemalteco de Migración
    'GY': 'CIPO',  # Guyana: Central Immigration and Passport Office
    'HT': 'DIE',   # Haiti: Directorate of Immigration and Emigration
    'HN': 'INM',   # Honduras: Instituto Nacional de Migración
    'NI': 'DGME',  # Nicaragua: Dirección General de Migración y Extranjería
    'PY': 'DIPN',  # Paraguay: Departamento de Identificaciones de la Policía Nacional
    'LC': 'ID',    # Saint Lucia: Immigration Department
    'VC': 'PID',   # Saint Vincent and the Grenadines: Passport and Immigration Department
    'SR': 'MFA',   # Suriname: Ministry of Foreign Affairs
    'TT': 'ID',    # Trinidad and Tobago: Immigration Division
    'UY': 'DNIC',  # Uruguay: Dirección Nacional de Identificación Civil
    'VE': 'SAIME', # Venezuela: SAIME
    
    # 大洋洲
    'FJ': 'DOI',   # Fiji: Department of Immigration
    'KI': 'MFAI',  # Kiribati: Ministry of Foreign Affairs and Immigration
    'MH': 'OAG',   # Marshall Islands: Office of the Attorney General
    'FM': 'DOJ',   # Micronesia: Department of Justice
    'NR': 'NI',    # Nauru: Nauru Immigration
    'PW': 'BOI',   # Palau: Bureau of Immigration
    'PG': 'ICA',   # Papua New Guinea: Immigration & Citizenship Authority
    'WS': 'MPMC',  # Samoa: Ministry of the Prime Minister and Cabinet
    'SB': 'MCILI', # Solomon Islands: Ministry of Commerce, Industry, Labour and Immigration
    'TO': 'MFA',   # Tonga: Ministry of Foreign Affairs
    'TV': 'MFA',   # Tuvalu: Ministry of Foreign Affairs
}

# ASN.1定义：DocumentType扩展结构
class DocumentTypeListSyntax(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('docTypeList', univ.SetOf(componentType=char.PrintableString()))
    )



# P-256 函数
def extract_ec_p256_private_key(pkcs8_der):
    """DER格式中提取P-256私钥S值（32字节）"""
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    
    # 使用cryptography库加载私钥
    private_key = load_der_private_key(pkcs8_der, password=None, backend=default_backend())
    
    # 确保是EC私钥
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("不是EC私钥")
    
    # 获取私钥数字（S值）
    private_numbers = private_key.private_numbers()
    s_value = private_numbers.private_value
    
    # 转换为32字节
    s_bytes = s_value.to_bytes(32, byteorder='big')
    
    if len(s_bytes) != 32:
        raise ValueError(f"Invalid P-256 private key length: {len(s_bytes)}")
    
    return s_bytes


def generate_international_identifier(dynamic_params, agency_acronyms):
    """生成国际标识符/机构代码"""
    country_2 = dynamic_params.get('country_code_2_letter', 'XX')
    country_3 = dynamic_params.get('country_code_3_letter', 'XXX')
    unit_id = dynamic_params.get('unit_id', 'VTE01')
    key_index = dynamic_params.get('key_index', 0)
    
    # 从 AGENCY_ACRONYMS 获取机构缩写
    agency = agency_acronyms.get(country_2, 'GOV')
    
    # 生成时间戳部分
    timestamp = datetime.now().strftime('%y%m%d')
    
    # 组合成最终的标识符
    identifier = f"{agency}{unit_id}{timestamp}-{key_index}"
    
    return identifier


class TLV:
    """TLV编解码器"""
    
    @staticmethod
    def encode(tag, value):
        """编码TLV结构"""
        if isinstance(tag, int):
            if tag <= 0xFF:
                tag_bytes = bytes([tag])
            elif tag <= 0xFFFF:
                tag_bytes = tag.to_bytes(2, 'big')
            else:
                raise ValueError("Tag too large")
        else:
            tag_bytes = tag
        
        # 编码长度
        length = len(value)
        if length < 128:
            length_bytes = bytes([length])
        elif length < 256:
            length_bytes = bytes([0x81, length])
        elif length < 65536:
            length_bytes = bytes([0x82, length >> 8, length & 0xFF])
        else:
            length_bytes = bytes([0x83, length >> 16, (length >> 8) & 0xFF, length & 0xFF])
        
        return tag_bytes + length_bytes + value


class CVCertificate:

    # 标签定义
    TAG_CV_CERTIFICATE = 0x7F21
    TAG_CERTIFICATE_BODY = 0x7F4E
    TAG_CERTIFICATE_VERSION = 0x5F29
    TAG_CAR = 0x42
    TAG_PUBLIC_KEY = 0x7F49
    TAG_CHR = 0x5F20
    TAG_CHAT = 0x7F4C
    TAG_EFFECTIVE_DATE = 0x5F25
    TAG_EXPIRATION_DATE = 0x5F24
    TAG_SIGNATURE = 0x5F37
    TAG_OID = 0x06
    TAG_MODULUS = 0x81
    TAG_EXPONENT = 0x82
    TAG_AUTHORIZATION = 0x53
    
    # 角色定义
    ROLE_CVCA = 0xC0  # 11xxxxxx
    ROLE_DV = 0x80    # 10xxxxxx
    ROLE_IS = 0x00    # 00xxxxxx
    
    # 权限位
    AUTH_READ_DG3 = 0x02  # 读取指纹
    AUTH_READ_DG4 = 0x01  # 读取虹膜
    
    def __init__(self):
        self.version = 0x00
        self.car = None
        self.public_key = None
        self.chr = None
        self.role = None
        self.auth_bits = 0x00
        self.effective_date = None
        self.expiration_date = None
    
    def encode_date(self, date):
        """编码日期为BCD格式 YYMMDD"""
        yy = date.year % 100
        mm = date.month
        dd = date.day
        
        # 正确的BCD编码：将十进制转为BCD
        # 38 → 0x38 (在BCD中表示为 3 和 8)
        return bytes([
            int(f"{yy:02d}", 16),  # 将38转为0x38
            int(f"{mm:02d}", 16),  # 将06转为0x06
            int(f"{dd:02d}", 16)   # 将17转为0x17
        ])
        
    def encode_public_key(self, public_key):
        """编码RSA公钥"""
        if isinstance(public_key, rsa.RSAPublicKey):
            public_numbers = public_key.public_numbers()
            modulus = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')
            exponent = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')
            
            # OID for id-TA-RSA-v1-5-SHA-256
            oid = bytes.fromhex('04007F00070202020201')
            
            # 修复：正确处理RSA-2048的大模数（256字节）
            if len(modulus) > 127:
                # 使用0x81 0x82格式表示256字节
                modulus_tlv = bytes([0x81, 0x82]) + len(modulus).to_bytes(2, 'big') + modulus
            else:
                modulus_tlv = bytes([0x81, len(modulus)]) + modulus
            
            content = (
                TLV.encode(self.TAG_OID, oid) +
                modulus_tlv +
                TLV.encode(self.TAG_EXPONENT, exponent)
            )
            
            return TLV.encode(self.TAG_PUBLIC_KEY, content)
        else:
            raise ValueError("Unsupported key type")
    
    def encode_chat(self):
        """编码证书持有者授权模板"""
        # OID for id-IS
        oid = bytes.fromhex('04007F00070202020202')
        
        # 授权字节
        auth_byte = self.role | self.auth_bits
        
        content = (
            TLV.encode(self.TAG_OID, oid) +
            TLV.encode(self.TAG_AUTHORIZATION, bytes([auth_byte]))
        )
        
        return TLV.encode(self.TAG_CHAT, content)
    
    def encode_body(self):
        """编码证书体"""
        body = (
            TLV.encode(self.TAG_CERTIFICATE_VERSION, bytes([self.version])) +
            TLV.encode(self.TAG_CAR, self.car) +
            self.encode_public_key(self.public_key) +
            TLV.encode(self.TAG_CHR, self.chr) +
            self.encode_chat() +
            TLV.encode(self.TAG_EFFECTIVE_DATE, self.encode_date(self.effective_date)) +
            TLV.encode(self.TAG_EXPIRATION_DATE, self.encode_date(self.expiration_date))
        )
        
        return TLV.encode(self.TAG_CERTIFICATE_BODY, body)
    
    def sign_and_encode(self, signing_key):
        """签名并编码完整证书"""
        body = self.encode_body()
        
        # 计算签名
        signature = signing_key.sign(
            body,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # 构建完整证书
        certificate = body + TLV.encode(self.TAG_SIGNATURE, signature)
        
        return TLV.encode(self.TAG_CV_CERTIFICATE, certificate)

class UnifiedCertChainGenerator:
    """统一证书链"""
    
    def __init__(self, custom_timestamp=None, org_code=None):
        self.country_2 = None
        self.specific_issuing_authority = None
        self.output_dir = None
        self.csca_private_key = None
        self.csca_cert = None
        self.dsc_private_key = None
        self.dsc_cert = None
        self.aa_keys = {}
        # 支持自定义时间戳（格式：YYYYMMDDHHMMSS或datetime对象）
        self.custom_timestamp = custom_timestamp
        # 支持自定义机构代码（如：DZHZB1210080-14）
        self.org_code = org_code
        
        self.ca_ec_keys = {}
        
    def get_country_input(self):
        """获取并验证输入的国家代码"""
        print(f"输入国家代码:")
        while True:
            country_code_input = input("国家代码 (2字母): ").upper().strip()
            
            # 核心修改：直接检查输入的代码是否存在于COUNTRY_DATA字典的键中
            if country_code_input in COUNTRY_DATA:
                self.country_2 = country_code_input
                # 从字典中获取国家全称并打印，提供反馈
                country_name = COUNTRY_DATA[self.country_2]['full_name']
                print(f"  ✓ 已识别国家: {country_name} ({self.country_2})")
                return # 验证成功，退出循环
            else:
                print(f"× 错误: 国家代码 '{country_code_input}' 未在COUNTRY_DATA字典中配置，请重新输入。")
    
    def create_output_directory(self):
        """创建输出目录"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = f"{self.country_2}_CertChain_{timestamp}"
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_csca_certificate(self):
        """生成CSCA根证书"""
        # --- 核心修改：在使用前先从主字典查找信息 ---
        try:
            country_info = COUNTRY_DATA[self.country_2]
        except KeyError:
            print(f"致命错误：无法为代码'{self.country_2}'生成CSCA，因为它不在COUNTRY_DATA中。")
            sys.exit(1)
        # CSCA私钥
        self.csca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
         
        # CSCA证书主体信息 - 现在引用从字典中查出的'country_info'
        csca_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_2),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{country_info['adjective']} Government"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Ministry of Foreign Affairs"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"{country_info['full_name']} Passport CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{country_info['full_name']} Passport Country Signing Certificate"),
        ])
        
        # CSCA证书有效期 - 修正：确保CSCA覆盖DSC签发时间且未过期
        # 策略：CSCA应该在DSC签发前几年就存在，且在DSC签发后还有足够长的有效期
        if self.custom_timestamp:
            if isinstance(self.custom_timestamp, str):
                base_time = datetime.strptime(self.custom_timestamp[:8], "%Y%m%d").replace(tzinfo=timezone.utc)
            else:
                base_time = self.custom_timestamp
        else:
            base_time = datetime.now(timezone.utc)
        
        # CSCA签发策略：在DSC签发前2-4年建立，有效期15年
        years_before_dsc = random.randint(2, 4)  # CSCA在DSC签发前2-4年就存在
        days_offset = random.randint(0, 365)
        
        # CSCA签发日期：DSC签发基准时间往前推2-4年
        not_valid_before = base_time - timedelta(days=(years_before_dsc * 365 + days_offset))
        # CSCA有效期15年，确保覆盖DSC的整个生命周期
        not_valid_after = not_valid_before + timedelta(days=5475)  # 15年
        
        # 生成证书序列号 - 核心修正：使用8字节
        csca_serial_number = int.from_bytes(os.urandom(8), 'big') & 0x7FFFFFFFFFFFFFFF
        
        # 构建CSCA证书
        self.csca_cert = (
            x509.CertificateBuilder()
            .subject_name(csca_subject)
            .issuer_name(csca_subject)  
            .public_key(self.csca_private_key.public_key())
            .serial_number(csca_serial_number)
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            # 基本约束：CA证书，路径长度1（可签发子CA）
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True
            )
            # 密钥用途：证书签名和CRL签名
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,      # 必需：证书签名
                    crl_sign=True,           # 必需：CRL签名
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            # 主体密钥标识符
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    self.csca_private_key.public_key()
                ),
                critical=False
            )

            # 使用SHA-256签名
            .sign(self.csca_private_key, hashes.SHA256(), default_backend())
        )
        
        print(f"√ CSCA证书生成完成")
        print(f"   CSCA Subject层次: 政府 → 外交部 → 护照CA")
        print(f"   CSCA有效期: {not_valid_before.strftime('%Y-%m-%d')} 到 {not_valid_after.strftime('%Y-%m-%d')}")
        if self.custom_timestamp:
            print(f"   DSC将在: {base_time.strftime('%Y-%m-%d')} 签发 (CSCA已提前建立)")
        
    
    def generate_dsc_certificate(self):
        """DSC证书"""
        # --- 核心修改：同样先从主字典查找信息 ---
        try:
            country_info = COUNTRY_DATA[self.country_2]
        except KeyError:
            print(f"致命错误：无法为代码'{self.country_2}'生成DSC，因为它不在COUNTRY_DATA中。")
            sys.exit(1)
        # 生成DSC私钥（2048位标准）
        self.dsc_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # 修复：生成唯一时间戳
        if self.custom_timestamp:
            if isinstance(self.custom_timestamp, str):
                # 如果是字符串格式，直接用
                timestamp = self.custom_timestamp
                # 解析自定义时间用于证书有效期
                custom_dt = datetime.strptime(self.custom_timestamp, "%Y%m%d%H%M%S")
                custom_dt = custom_dt.replace(tzinfo=timezone.utc)
            elif isinstance(self.custom_timestamp, datetime):
                # 如果是datetime对象，格式化
                timestamp = self.custom_timestamp.strftime("%Y%m%d%H%M%S")
                custom_dt = self.custom_timestamp
                if custom_dt.tzinfo is None:
                    custom_dt = custom_dt.replace(tzinfo=timezone.utc)
            else:
                raise ValueError("custom_timestamp必须是字符串(YYYYMMDDHHMMSS)或datetime对象")
        else:
            # 使用当前时间
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            custom_dt = datetime.now(timezone.utc)
        
        cn_value = f"CDS {self.org_code}-{timestamp}"
        print(f"   使用固定格式生成CN: {cn_value}")
            
        # DSC Subject结构 - 先定义不包含可选OU的基础列表
        dsc_subject_attributes = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_2),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{country_info['adjective']} Government"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.specific_issuing_authority),  # 必须输入的OU
            # 注意：具体签发机构OU先不加进来
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Passport"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn_value),
        ]

        dsc_subject = x509.Name(dsc_subject_attributes)

        print(f"   DSC Subject层次: 国家 -> 政府 -> 顶层机构 -> 具体签发机构 -> 业务")
        
        # 证书有效期（10年）- 修正：真实护照DSC有效期为10年
        dsc_not_valid_before = custom_dt - timedelta(hours=1)
        dsc_not_valid_after = dsc_not_valid_before + timedelta(days=3650)  # 10年
        
        # 生成证书序列号 - 核心修复：使用8字节
        dsc_serial_number = int.from_bytes(os.urandom(8), 'big') & 0x7FFFFFFFFFFFFFFF
        
        # DocumentType扩展
        doc_type_list = DocumentTypeListSyntax()
        doc_type_list['version'] = 0
        doc_type_list['docTypeList'].setComponentByPosition(0, char.PrintableString('P'))
        doc_type_der = encoder.encode(doc_type_list)
        
        # 构建DSC证书 由CSCA签发
        self.dsc_cert = (
            x509.CertificateBuilder()
            .subject_name(dsc_subject)
            .issuer_name(self.csca_cert.subject)  # CSCA签发
            .public_key(self.dsc_private_key.public_key())
            .serial_number(dsc_serial_number)
            .not_valid_before(dsc_not_valid_before)
            .not_valid_after(dsc_not_valid_after)
            # 基本约束：非CA证书
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            # 密钥用途：数字签名（SOD签名）
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,  # 必需：数字签名
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            # 主体密钥标识符
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    self.dsc_private_key.public_key()
                ),
                critical=False
            )
            # 授权密钥标识符（链接到CSCA）
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.csca_private_key.public_key()
                ),
                critical=False
            )
            #  修复：根据ICAO 9303第12部分表6，DSC证书禁止使用ExtKeyUsage扩展
            #  修复：删除未确认的证书策略OID，保持标准合规
            # DocumentType扩展（ICAO标准）
            .add_extension(
                x509.UnrecognizedExtension(
                    oid=x509.ObjectIdentifier("2.23.136.1.1.6.2"),
                    value=doc_type_der
                ),
                critical=False
            )
            # 由CSCA私钥签名
            .sign(self.csca_private_key, hashes.SHA256(), default_backend())
        )
        
        print(f"√ DSC证书生成完成")
        print(f"   DSC有效期: {dsc_not_valid_before.strftime('%Y-%m-%d')} 到 {dsc_not_valid_after.strftime('%Y-%m-%d')} (10年)")
        
    
    def generate_aa_keys(self):
        """AA密钥"""
        
        # 修复：根据ICAO 9303标准，AA不需要X.509证书，只需要密钥用于DG15
        # 硬编码128字节
        rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,  # 1024位 = 128字节完美匹配
            backend=default_backend()
        )
        
        self.aa_keys = {
            'rsa_1024': {'private': rsa_private_key, 'public': rsa_private_key.public_key()}
        }
        
    def save_certificates_and_keys(self):        
        # 保存CSCA根证书和私钥仅DER
        with open(os.path.join(self.output_dir, f"{self.country_2}_CSCA_private.der"), 'wb') as f:
            f.write(self.csca_private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(os.path.join(self.output_dir, f"{self.country_2}_CSCA_cert.der"), 'wb') as f:
            f.write(self.csca_cert.public_bytes(serialization.Encoding.DER))
        
        # 保存DSC证书和私钥仅DER
        with open(os.path.join(self.output_dir, f"{self.country_2}_DSC_private.der"), 'wb') as f:
            f.write(self.dsc_private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(os.path.join(self.output_dir, f"{self.country_2}_DSC_cert.der"), 'wb') as f:
            f.write(self.dsc_cert.public_bytes(serialization.Encoding.DER))
        
        #  修复：保存AA私钥
        with open(os.path.join(self.output_dir, f"{self.country_2}_AA_RSA_1024_private.der"), 'wb') as f:
            f.write(self.aa_keys['rsa_1024']['private'].private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def generate_certificate_chain_packages(self):
        
        # 1. 生成DSC证书链的PFX文件（包含CSCA+DSC+私钥）
        from cryptography.hazmat.primitives import serialization
        
        # DSC PFX（完整证书链）
        dsc_pfx_data = serialization.pkcs12.serialize_key_and_certificates(
            name=f"{self.country_2} DSC Chain".encode('utf-8'),
            key=self.dsc_private_key,
            cert=self.dsc_cert,
            cas=[self.csca_cert],  # 包含CA证书
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open(os.path.join(self.output_dir, f"{self.country_2}_DSC_Chain.pfx"), 'wb') as f:
            f.write(dsc_pfx_data)
        
        
##################    核心修正    ###########################    
    def generate_dg15_files(self):                ##########     
        """生成DG15文件"""                           ########
                                                    ########
        print(f" 生成DG15文件")                       #######
                                                    ########       
        # 1. 获取 SubjectPublicKeyInfo - 从RSA-1024公钥获取
        subject_public_key_info_der = self.aa_keys['rsa_1024']['public'].public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 2. 直接构造 APPLICATION 15 TLV Tag 0x6F
        # 不需要额外SEQUENCE包装，SubjectPublicKeyInfo本身就是SEQUENCE
        dg15_tag = b'\x6F'
        dg15_content = subject_public_key_info_der  # 直接用，不继续包装
        
        # 3.计算DG15长度内容
        content_length = len(dg15_content)
        if content_length < 0x80:
            length_bytes = bytes([content_length])
        elif content_length <= 0xFF:
            length_bytes = bytes([0x81, content_length])
        else: # 假设长度不超过0xFFFF
            length_bytes = bytes([0x82, (content_length >> 8) & 0xFF, content_length & 0xFF])

        # 4. 组装最终DG15
        dg15_data = dg15_tag + length_bytes + dg15_content
        
        # 5. 打印最终信息
        print(f"   - 准备写入 DG15.bin, 总大小: {len(dg15_data)} 字节")
        print(f"   - 结构: 0x6F + L + SubjectPublicKeyInfo (RSA-1024)")
        print(f"    DG15.bin: {len(dg15_data)} 字节 (APPLICATION 15格式)")
        
        # 6. 保存文件
        self.save_dg15_file(dg15_data)
        
        # 7. 返回生成的数据
        return dg15_data
    
    def save_dg15_file(self, dg15_data):
        """保存DG15文件"""
        file_path = os.path.join(self.output_dir, "DG15.bin")
        with open(file_path, 'wb') as f:
            f.write(dg15_data)
        print(f"    已保存: {file_path}")
    
    def generate_eac_components(self):
        """生成EAC组件"""
        print("\n 生成EAC组件")
        
        # 1. 生成CVCA证书链
     #  self.generate_cvca_certificate()
     #  self.generate_dv_certificate()
     #  self.generate_is_certificate()
        
        # 生成CA的EC密钥对
        self.generate_ca_ec_keys()
        
        # 生成DG14文件
        self.generate_dg14_file()
        
        print("✓ CA/DG14 生成完成")
    
    def generate_cvca_certificate(self):
        """生成CVCA (Country Verifying CA) 证书"""
        print("  → 生成CVCA证书")
        
        # 生成RSA 2048密钥
        self.cvca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # 获取基准时间（与CSCA/DSC体系同步）
        if hasattr(self, 'custom_timestamp') and self.custom_timestamp:
            if isinstance(self.custom_timestamp, str):
                base_time = datetime.strptime(self.custom_timestamp[:8], "%Y%m%d").replace(tzinfo=timezone.utc)
            else:
                base_time = self.custom_timestamp
                if base_time.tzinfo is None:
                    base_time = base_time.replace(tzinfo=timezone.utc)
        else:
            base_time = datetime.now(timezone.utc)
        
        # CVCA建立时间：比CSCA晚约6-12个月（验证方体系稍后建立）
        # 但仍然早于护照签发（base_time）
        months_after_csca = random.randint(6, 12)
        days_before_base = 2 * 365 - (months_after_csca * 30)  # 约2年前，但比CSCA晚
        days_offset = random.randint(-15, 15)  # 小幅随机偏移
        
        cvca_effective_date = base_time - timedelta(days=(days_before_base + days_offset))
        cvca_expiration_date = cvca_effective_date + timedelta(days=5475)  # 15年
        
        # 创建CV证书
        cv_cert = CVCertificate()
        cv_cert.version = 0x00
        cv_cert.car = f"CVCA{self.country_3}01".encode('utf-8')[:16].ljust(16, b'\x00')
        cv_cert.chr = cv_cert.car  # CVCA自引用
        cv_cert.public_key = self.cvca_private_key.public_key()
        cv_cert.role = CVCertificate.ROLE_CVCA
        cv_cert.auth_bits = 0x00
        cv_cert.effective_date = cvca_effective_date
        cv_cert.expiration_date = cvca_expiration_date
        
        # 签名并编码
        self.cvca_cert_der = cv_cert.sign_and_encode(self.cvca_private_key)
        
        # 保存证书
        filename = f"{self.country_2}_cvca_cert.cvcert"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(self.cvca_cert_der)
        
        print(f"    ✓ CVCA生成完成: {filename}")
        print(f"    ✓ CVCA有效期: {cvca_effective_date.strftime('%Y-%m-%d')} 至 {cvca_expiration_date.strftime('%Y-%m-%d')} (15年)")

    def generate_dv_certificate(self):
        """生成DV (Document Verifier) 证书"""
        print("  → 生成DV证书...")
        
        # 生成RSA 2048密钥
        self.dv_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # 获取基准时间
        if hasattr(self, 'custom_timestamp') and self.custom_timestamp:
            if isinstance(self.custom_timestamp, str):
                base_time = datetime.strptime(self.custom_timestamp[:8], "%Y%m%d").replace(tzinfo=timezone.utc)
            else:
                base_time = self.custom_timestamp
                if base_time.tzinfo is None:
                    base_time = base_time.replace(tzinfo=timezone.utc)
        else:
            base_time = datetime.now(timezone.utc)
        
        # DV建立时间：护照开始流通后1-3个月
        days_after_base = random.randint(30, 90)
        
        dv_effective_date = base_time + timedelta(days=days_after_base)
        dv_expiration_date = dv_effective_date + timedelta(days=1825)  # 5年
        
        # 创建CV证书
        cv_cert = CVCertificate()
        cv_cert.version = 0x00
        cv_cert.car = f"CVCA{self.country_3}01".encode('utf-8')[:16].ljust(16, b'\x00')
        cv_cert.chr = f"DV{self.country_3}001".encode('utf-8')[:16].ljust(16, b'\x00')
        cv_cert.public_key = self.dv_private_key.public_key()
        cv_cert.role = CVCertificate.ROLE_DV
        cv_cert.auth_bits = CVCertificate.AUTH_READ_DG3 | CVCertificate.AUTH_READ_DG4
        cv_cert.effective_date = dv_effective_date
        cv_cert.expiration_date = dv_expiration_date
        
        # 使用CVCA签名
        self.dv_cert_der = cv_cert.sign_and_encode(self.cvca_private_key)
        
        # 保存证书
        filename = f"{self.country_2}_dv_cert.cvcert"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(self.dv_cert_der)
        
        print(f"    ✓ DV生成完成: {filename}")
        print(f"    ✓ DV有效期: {dv_effective_date.strftime('%Y-%m-%d')} 至 {dv_expiration_date.strftime('%Y-%m-%d')} (5年)")

    def generate_is_certificate(self):
        """生成IS (Inspection System) 证书"""
        print("  → 生成IS证书...")
        
        # 生成RSA 2048密钥
        self.is_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # 获取基准时间
        if hasattr(self, 'custom_timestamp') and self.custom_timestamp:
            if isinstance(self.custom_timestamp, str):
                base_time = datetime.strptime(self.custom_timestamp[:8], "%Y%m%d").replace(tzinfo=timezone.utc)
            else:
                base_time = self.custom_timestamp
                if base_time.tzinfo is None:
                    base_time = base_time.replace(tzinfo=timezone.utc)
        else:
            base_time = datetime.now(timezone.utc)
        
        # IS建立时间：比DV晚1-3个月（实际边检部署）
        days_after_base = random.randint(60, 180)  # 2-6个月
        
        is_effective_date = base_time + timedelta(days=days_after_base)
        is_expiration_date = is_effective_date + timedelta(days=730)  # 2年
        
        # 创建CV证书
        cv_cert = CVCertificate()
        cv_cert.version = 0x00
        cv_cert.car = f"DV{self.country_3}001".encode('utf-8')[:16].ljust(16, b'\x00')
        cv_cert.chr = f"IS{self.country_3}BC01".encode('utf-8')[:16].ljust(16, b'\x00')  # BC = Border Control
        cv_cert.public_key = self.is_private_key.public_key()
        cv_cert.role = CVCertificate.ROLE_IS
        cv_cert.auth_bits = CVCertificate.AUTH_READ_DG3 | CVCertificate.AUTH_READ_DG4
        cv_cert.effective_date = is_effective_date
        cv_cert.expiration_date = is_expiration_date
        
        # 使用DV签名
        self.is_cert_der = cv_cert.sign_and_encode(self.dv_private_key)
        
        # 保存证书
        filename = f"{self.country_2}_is_cert.cvcert"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(self.is_cert_der)
        
        print(f"    ✓ IS生成完成: {filename}")
        print(f"    ✓ IS有效期: {is_effective_date.strftime('%Y-%m-%d')} 至 {is_expiration_date.strftime('%Y-%m-%d')} (2年)")
    
    def generate_ca_ec_keys(self):
        """生成CA的EC P-256密钥对"""
        print("  → 生成CA密钥对 (EC P-256)...")
        
        # 生成P-256密钥
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        
        # 保存私钥（DER格式，用于阶段零注入）
        private_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # 获取公钥点
        public_numbers = public_key.public_numbers()
        x_bytes = public_numbers.x.to_bytes(32, 'big')  # P-256使用32字节
        y_bytes = public_numbers.y.to_bytes(32, 'big')  # P-256使用32字节
        public_point = b'\x04' + x_bytes + y_bytes  # 非压缩格式
        
        self.ca_ec_keys = {
            'private': private_key,
            'public': public_key,
            'private_der': private_der,
            'public_point': public_point
        }
        
        # 保存私钥（PKCS#8格式）
        filename = f"{self.country_2}_CA_P256_private.der"  # 改为P256
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(private_der)
        print(f"    ✓ CA私钥已保存: {filename}")
        
        # 保存公钥
        filename_pub = f"{self.country_2}_CA_P256_public.bin"  # 改为P256
        filepath_pub = os.path.join(self.output_dir, filename_pub)
        with open(filepath_pub, 'wb') as f:
            f.write(public_point)
        print(f"    ✓ CA公钥已保存: {filename_pub} (65字节)")  # P-256是65字节（1+32+32）
        
        # 提取并保存S值（用于卡片注入）
        try:
            s_value = extract_ec_p256_private_key(private_der)  # 改为p256提取函数
            filename_s = f"{self.country_2}_CA_P256_private_s.bin"  # 改为P256
            filepath_s = os.path.join(self.output_dir, filename_s)
            with open(filepath_s, 'wb') as f:
                f.write(s_value)
            print(f"    ✓ CA私钥S值已保存: {filename_s} (32字节)")  # P-256是32字节
        except Exception as e:
            print(f"      警告: 无法提取S值 - {e}")
            

    def encode_length(self, length: int) -> bytes:
        """
        编码BER-TLV长度字段
        """
        if length < 0x80:
            # 短格式：0-127字节
            return bytes([length])
        elif length <= 0xFF:
            # 长格式：128-255字节
            return bytes([0x81, length])
        elif length <= 0xFFFF:
            # 长格式：256-65535字节
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        else:
            raise ValueError(f"Length is too large: {length}")
            
    
    def generate_dg14_file(self):
        """生成DG14 - 最终修正版V2，解决双重封装问题"""
        print("  → 生成DG14文件 (V-Final-2)...")
        
        ca_public_key = self.ca_ec_keys['public']
        
        # 1. SubjectPublicKeyInfo
        subject_public_key_info = ca_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 2. Protocol OID: DER TLV
        ca_protocol_oid_tlv = bytes.fromhex('060A04007F00070202030102')

        # 3. KeyId: 完整的DER TLV
        key_id_tlv = bytes.fromhex('020101')

        # 4. Version: 完整的DER TLV
        chip_auth_info_version_tlv = bytes.fromhex('020101')


        # 5. 构建 ChipAuthenticationPublicKeyInfo 的 *内容* (Content)
        # 顺序: OID -> 公钥 -> KeyId
        chip_auth_public_key_info_content = (
            ca_protocol_oid_tlv + 
            subject_public_key_info + 
            key_id_tlv
        )
        # 用SEQUENCE(0x30)封装 *内容*，得到一个完整的SecurityInfo对象
        chip_auth_public_key_info = bytes([0x30]) + self.encode_length(len(chip_auth_public_key_info_content)) + chip_auth_public_key_info_content
        
        # 6. 构建 ChipAuthenticationInfo 的 *内容*
        chip_auth_info_content = (
            ca_protocol_oid_tlv + 
            chip_auth_info_version_tlv
        )
        # 用SEQUENCE(0x30)封装 *内容*
        chip_auth_info = bytes([0x30]) + self.encode_length(len(chip_auth_info_content)) + chip_auth_info_content
        
        # 7. SecurityInfos SET
        security_infos_content = chip_auth_public_key_info + chip_auth_info
        security_infos = bytes([0x31]) + self.encode_length(len(security_infos_content)) + security_infos_content
        
        # 8. DG14
        dg14 = bytes([0x6E]) + self.encode_length(len(security_infos)) + security_infos
        
        # 9. 保存
        filename = "DG14.bin"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(dg14)
        
        print(f"    ✓ DG14生成完成: {filename} ({len(dg14)} 字节)")
    
    
    def collect_all_parameters(self):
        """收集所有生成参数"""
        print("="*60)
        print(" 统一证书链 - 参数设置")
        print("="*60)
        
        #1 获取国家代码
        self.get_country_input()
        
        # 2时间戳
        if not self.custom_timestamp:
            print(f"\n 时间戳设置:")
            while True:
                timestamp_input = input("输入时间戳 (YYYYMMDD 或 YYYYMMDDHHMMSS): ").strip()
                if len(timestamp_input) == 8:
                    self.custom_timestamp = timestamp_input + "120000"
                    break
                elif len(timestamp_input) == 14:
                    self.custom_timestamp = timestamp_input
                    break
                else:
                    print("× 无效格式，请重新输入")
        
        # 步骤 3: 交互式地获取动态信息
        print(f"\n 动态标识信息输入:")
        unit_id = input("  请输入单元ID (例如: VTE01): ").strip()
        key_index_str = input("  请输入密钥索引 (例如: 2): ").strip()
        
        try:
            # 将输入的密钥索引转为整数，如果失败则默认为0
            key_index_int = int(key_index_str)
        except ValueError:
            print(f"  警告: 无效的密钥索引 '{key_index_str}'，将使用7。")
            key_index_int = 7

        # 步骤 4: 程序自动组合生成'机构代码 (org_code)'
        # 创建一个临时的参数字典
        dynamic_params = {
            "country_code_2_letter": self.country_2,
            "country_code_3_letter": COUNTRY_DATA[self.country_2]['alpha3'],
            "unit_id": unit_id,
            "key_index": key_index_int
        }
        
        # 注意: generate_international_identifier 函数需要传入 AGENCY_ACRONYMS 字典
        self.org_code = generate_international_identifier(dynamic_params, AGENCY_ACRONYMS)
        
        print(f"  ✓ 程序已自动组合机构代码为: {self.org_code}")

        # 步骤 5: 获取DSC特定的签发机构OU
        print(f"\n DSC签发机构设置:")
        print("  OU（必填）")
        print("  看PSD的签发机构")
        while True:
            self.specific_issuing_authority = input("输入签发OU: ").strip()
            if self.specific_issuing_authority:
                break
            else:    
                print("  × 此项为必填，请输入签发机构OU")
                
    # in class UnifiedCertChainGenerator:
    def confirm_parameters(self):
        """确认生成参数"""
        #新增：先从主字典查找国家信息
        try:
            country_info = COUNTRY_DATA[self.country_2]
        except KeyError:
            # 这是一个安全检查，虽然get_country_input已经保证了country_2的有效性
            print(f"致命错误: 无法为代码 '{self.country_2}' 确认参数，因为它不在COUNTRY_DATA中。")
            return False # 返回False以中止流程

        print("\n" + "="*60)
        print(" 参数确认")
        print("="*60)
        
        # 核心修改：使用查找到的 country_info 打印信息
        print(f"️  国家: {country_info['full_name']} ({self.country_2}/{country_info['alpha3']})")
        
        formatted_time = f"{self.custom_timestamp[:4]}-{self.custom_timestamp[4:6]}-{self.custom_timestamp[6:8]} {self.custom_timestamp[8:10]}:{self.custom_timestamp[10:12]}:{self.custom_timestamp[12:14]}"
        print(f" 时间戳: {formatted_time}")
            
        if self.org_code:
            print(f" 机构代码: {self.org_code}")
        
        if self.specific_issuing_authority:
            print(f" DSC 签发机构: {self.specific_issuing_authority}")
        
        print(f" EAC组件:  已启用 (CA/TA + DG14)")
        print("="*60)
        
        while True:
            confirm = input(" 生成证书链? (y/N): ").strip().lower()
            if confirm in ['y', 'yes']:
                return True
            elif confirm in ['n', 'no', '']:
                print("× 取消生成")
                return False
            else:
                print("× 输入 y 或 n")

    def generate_complete_chain(self):
        """生成完整证书链"""
        # 收集所有参数
        self.collect_all_parameters()
        
        # 确认参数
        if not self.confirm_parameters():
            return None
        
        print("\n 开始生成证书链")
        print("="*60)
        
        self.create_output_directory()
        self.generate_csca_certificate()
        self.generate_dsc_certificate()
        self.generate_aa_keys()  # 修复：更新函数名
        self.save_certificates_and_keys()
        self.generate_certificate_chain_packages()
        self.generate_dg15_files()
        
        self.generate_eac_components()  # 直接调用，不判断
        
        print(f"\n {self.country_2} 证书链生成完成: {self.output_dir}")
        
        return self.output_dir

if __name__ == "__main__":
    try:
        # 支持命令行参数
        custom_timestamp = None
        org_code = None
        
        # 解析命令行参数
        args = sys.argv[1:]
        i = 0
        while i < len(args):
            if args[i] == "--timestamp" or args[i] == "-t":
                if i + 1 < len(args):
                    timestamp_arg = args[i + 1]
                    if len(timestamp_arg) == 8:
                        custom_timestamp = timestamp_arg + "120000"
                    elif len(timestamp_arg) == 14:
                        custom_timestamp = timestamp_arg
                    else:
                        print(f"错误：无效的时间戳格式 '{timestamp_arg}'")
                        print("支持格式：YYYYMMDD 或 YYYYMMDDHHMMSS")
                        sys.exit(1)
                    i += 2
                else:
                    print("错误：--timestamp 需要一个参数")
                    sys.exit(1)
            elif args[i] == "--org-code" or args[i] == "-o":
                if i + 1 < len(args):
                    org_code = args[i + 1]
                    i += 2
                else:
                    print("错误：--org-code 需要一个参数")
                    sys.exit(1)
            elif args[i] == "--help" or args[i] == "-h":
                print("证书链边检级增强")
                print("\n用法:")
                print("  python unified_cert_chain.py [选项]")
                print("\n选项:")
                print("  --timestamp, -t <YYYYMMDD|YYYYMMDDHHMMSS>  设置时间戳 (必需)")
                print("  --org-code, -o <代码>                       设置机构代码")
                print("  --help, -h                                  显示帮助")
                print("\n说明:")
                print("  EAC组件(CA/TA)启用")
                sys.exit(0)
            else:
                # 向后兼容：如果只有一个参数，当作时间戳
                if len(args) == 1 and not custom_timestamp:
                    timestamp_arg = args[0]
                    if len(timestamp_arg) == 8:
                        custom_timestamp = timestamp_arg + "120000"
                    elif len(timestamp_arg) == 14:
                        custom_timestamp = timestamp_arg
                    else:
                        print(f"错误：无效的时间戳格式 '{timestamp_arg}'")
                        sys.exit(1)
                else:
                    print(f"错误：未知参数 '{args[i]}'")
                    print("\n用法：")
                    print("  python unified_cert_chain.py [时间戳]")
                    print("  python unified_cert_chain.py --timestamp YYYYMMDD --org-code 机构代码")
                    print("\n示例：")
                    print("  python unified_cert_chain.py 20230704")
                    print("  python unified_cert_chain.py --timestamp 20230704063932 --org-code DZHZB1210080-14")
                    sys.exit(1)
                i += 1
        
        if custom_timestamp:
            print(f"自定义时间戳：{custom_timestamp}")
        if org_code:
            print(f"使用机构代码：{org_code}")
        
        generator = UnifiedCertChainGenerator(custom_timestamp, org_code)
        output_dir = generator.generate_complete_chain()
        
        if output_dir:
            print(f"\n 完整证书链已保存在: {output_dir}")
            
            if custom_timestamp:
                print(f"   DSC时间戳：{custom_timestamp}")
                print(f"   提示：匹配MRZ的签发日期，审核机制大概率会检查")
            if org_code:
                print(f"   机构代码：{org_code}")
        else:
            print(" 生成已取消")
            sys.exit(0)
            
    except Exception as e:
        print(f"\n 生成失败: {e}")
        import traceback
        traceback.print_exc() 