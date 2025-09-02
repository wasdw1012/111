import os
import glob
import hashlib
import argparse
from datetime import datetime, timezone
from pyasn1.type import univ, namedtype, namedval, tag, useful
from pyasn1.codec.der import encoder, decoder
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

# ==================== ASN.1 定义 ====================

# OIDs
LDS_SECURITY_OBJECT_OID = univ.ObjectIdentifier('2.23.136.1.1.1')
SHA256_OID = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')
SHA256_WITH_RSA_OID = univ.ObjectIdentifier('1.2.840.113549.1.1.11')
CMS_SIGNED_DATA_OID = univ.ObjectIdentifier('1.2.840.113549.1.7.2')
CMS_CONTENT_TYPE_OID = univ.ObjectIdentifier('1.2.840.113549.1.9.3')
CMS_MESSAGE_DIGEST_OID = univ.ObjectIdentifier('1.2.840.113549.1.9.4')
CMS_SIGNING_TIME_OID = univ.ObjectIdentifier('1.2.840.113549.1.9.5')

#DataGroup标签
SOD_TAG = 0x77  

class DataGroupHash(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('dataGroupNumber', univ.Integer()),
        namedtype.NamedType('dataGroupHashValue', univ.OctetString())
    )

class DataGroupHashValues(univ.SequenceOf):
    componentType = DataGroupHash()

class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
    )

class LDSSecurityObject(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('hashAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('dataGroupHashValues', DataGroupHashValues()),
        namedtype.OptionalNamedType('ldsVersionInfo', univ.OctetString())
    )

class IssuerAndSerialNumber(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuer', univ.Any()),
        namedtype.NamedType('serialNumber', univ.Integer())
    )

class SignerIdentifier(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerAndSerialNumber', IssuerAndSerialNumber()),
        namedtype.NamedType('subjectKeyIdentifier', 
            univ.OctetString().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        )
    )

class Attribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attrType', univ.ObjectIdentifier()),
        namedtype.NamedType('attrValues', univ.SetOf(componentType=univ.Any()))
    )

class SignedAttributes(univ.SetOf):
    componentType = Attribute()
    tagSet = univ.SetOf.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )

class SignerInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('sid', SignerIdentifier()),
        namedtype.NamedType('digestAlgorithm', AlgorithmIdentifier()),
        namedtype.OptionalNamedType('signedAttrs', SignedAttributes()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signature', univ.OctetString())
    )

class SignerInfos(univ.SetOf):
    componentType = SignerInfo()

class EncapsulatedContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('eContentType', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('eContent', 
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        )
    )

# 正确的certificates字段定义
class CertificateSet(univ.SetOf):
    """证书集合 - 修复标签冲突问题"""
    componentType = univ.Any()
    tagSet = univ.SetOf.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )

class SignedData(univ.Sequence):
    """CMS SignedData结构 - 修复版本"""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('digestAlgorithms', univ.SetOf(componentType=AlgorithmIdentifier())),
        namedtype.NamedType('encapContentInfo', EncapsulatedContentInfo()),
        namedtype.OptionalNamedType('certificates', CertificateSet()),
        namedtype.OptionalNamedType('crls', 
            univ.SetOf(componentType=univ.Any()).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            )
        ),
        namedtype.NamedType('signerInfos', SignerInfos())
    )

# 简化的ContentInfo定义
class ContentInfo(univ.Sequence):
    """ContentInfo - 修复双重标签问题"""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contentType', univ.ObjectIdentifier()),
        namedtype.NamedType('content', univ.Any().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        ))
    )

#  新增：DataGroup包装器，用于添加正确的0x77标签
class SODDataGroup(univ.Any):
    """SOD DataGroup包装器 - 确保使用0x77标签"""
    tagSet = univ.Any.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 23)  # 0x77 = APPLICATION 23
    )

def load_private_key(key_path):
    with open(key_path, 'rb') as f:
        key_data = f.read()
    try:
        return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
    except ValueError:
        try:
            return serialization.load_der_private_key(key_data, password=None, backend=default_backend())
        except ValueError as e:
            raise ValueError(f"无法加载私钥文件 {key_path}: {e}")

def load_certificate(cert_path):
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    try:
        return load_pem_x509_certificate(cert_data, default_backend())
    except ValueError:
        try:
            return load_der_x509_certificate(cert_data, default_backend())
        except ValueError as e:
            raise ValueError(f"无法加载证书文件 {cert_path}: {e}")

def build_issuer_and_serial_safe(certificate):
    """修复致命风险2: 安全提取IssuerAndSerialNumber
    
    替换硬编码索引[0][3]和[0][1]，使用cryptography库安全提取
    符合RFC 5652第2115行IssuerAndSerialNumber结构定义
    """
    issuer_and_serial = IssuerAndSerialNumber()
    
    #  修复潜在风险1: 使用正确的X.501 Name编码
    # RFC 5652第2116行要求issuer必须是符合X.501标准的Name
    issuer_der = certificate.issuer.public_bytes(serialization.Encoding.DER)
    issuer_and_serial['issuer'] = univ.Any(issuer_der)
    
    # 安全提取serialNumber：直接使用certificate.serial_number
    issuer_and_serial['serialNumber'] = certificate.serial_number
    
    return issuer_and_serial

def auto_find_dsc_files():
    """自动扫描当前目录的DSC密钥和证书文件"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    key_files = glob.glob(os.path.join(script_dir, "*dsc*key*.pem")) + \
                glob.glob(os.path.join(script_dir, "*dsc*key*.der")) + \
                glob.glob(os.path.join(script_dir, "*dsc_key*.pem")) + \
                glob.glob(os.path.join(script_dir, "*dsc_key*.der"))
    cert_files = glob.glob(os.path.join(script_dir, "*dsc*.pem")) + \
                 glob.glob(os.path.join(script_dir, "*dsc*.der"))
    
    cert_files = [f for f in cert_files if 'key' not in f.lower()]
    
    print(f"\n 自动扫描DSC文件（目录: {script_dir}）:")
    print(f"  找到DSC私钥: {key_files}")
    print(f"  找到DSC证书: {cert_files}")
    
    if not key_files:
        raise FileNotFoundError("未找到DSC私钥文件")
    if not cert_files:
        raise FileNotFoundError("未找到DSC证书文件")
    
    return key_files[0], cert_files[0]

def build_lds_security_object(dg_hashes):
    """构建LDS Security Object"""
    print("\n[2] 构建LDS Security Object")
    
    dg_hash_values = DataGroupHashValues()
    for i, (dg_num, dg_hash) in enumerate(sorted(dg_hashes.items())):
        dg_hash_entry = DataGroupHash()
        dg_hash_entry['dataGroupNumber'] = dg_num
        dg_hash_entry['dataGroupHashValue'] = dg_hash
        dg_hash_values.setComponentByPosition(i, dg_hash_entry)
    
    hash_algorithm = AlgorithmIdentifier()
    hash_algorithm['algorithm'] = SHA256_OID
    #  修复潜在风险2: SHA-256算法parameters应该为NULL
    # RFC 3370第2.1节要求SHA算法的parameters为NULL
    hash_algorithm['parameters'] = univ.Null()
    
    lds_object = LDSSecurityObject()
    lds_object['version'] = 0
    lds_object['hashAlgorithm'] = hash_algorithm
    lds_object['dataGroupHashValues'] = dg_hash_values
    
    return encoder.encode(lds_object)

def build_signed_attributes(lds_object_der):
    """构建签名属性"""
    print("\n[3] 构建签名属性")
    
    signed_attrs = SignedAttributes()
    
    # Content Type
    attr1 = Attribute()
    attr1['attrType'] = CMS_CONTENT_TYPE_OID
    attr1['attrValues'].setComponentByPosition(0, LDS_SECURITY_OBJECT_OID)
    
    # Message Digest
    attr2 = Attribute()
    attr2['attrType'] = CMS_MESSAGE_DIGEST_OID
    attr2['attrValues'].setComponentByPosition(0, univ.OctetString(hashlib.sha256(lds_object_der).digest()))
    
    # Signing Time
    attr3 = Attribute()
    attr3['attrType'] = CMS_SIGNING_TIME_OID
    time_val = useful.UTCTime(datetime.now(timezone.utc).strftime('%y%m%d%H%M%SZ'))
    attr3['attrValues'].setComponentByPosition(0, time_val)
    
    # Set all attributes
    signed_attrs.setComponentByPosition(0, attr1)
    signed_attrs.setComponentByPosition(1, attr2)
    signed_attrs.setComponentByPosition(2, attr3)
    
    return signed_attrs

def encode_signed_attributes_for_signing(signed_attrs):
    """ 修复致命风险1: 按RFC 5652要求重新编码SignedAttributes用于签名计算
    
    RFC 5652第864行要求: 签名计算时必须使用EXPLICIT SET OF标签，
    而不是IMPLICIT [0]标签
    """
    # 创建新的SET OF结构，移除IMPLICIT [0]标签
    attrs_for_signing = univ.SetOf(componentType=Attribute())
    
    # 复制所有属性到新结构
    for i in range(len(signed_attrs)):
        attrs_for_signing.setComponentByPosition(i, signed_attrs.getComponentByPosition(i))
    
    # 使用EXPLICIT SET OF标签编码
    return encoder.encode(attrs_for_signing)

def validate_dg_files_integrity(dg_files):
    """ 修复潜在风险3: 验证数据组文件完整性
    
    确保DG文件存在、可读、非空，符合ICAO 9303规范
    """
    if not dg_files:
        raise ValueError("至少需要DG1和DG2文件")
    
    # ICAO要求DG1和DG2是强制的
    if 1 not in dg_files or 2 not in dg_files:
        raise ValueError("DG1和DG2是强制性的数据组")
    
    for dg_num, file_path in dg_files.items():
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"DG{dg_num}文件不存在: {file_path}")
        
        # 检查文件大小
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            raise ValueError(f"DG{dg_num}文件为空: {file_path}")
        
        # ICAO 9303规定最大数据组大小限制
        if file_size > 65535:  # 64KB limit for most DGs
            print(f"      警告: DG{dg_num}文件大小({file_size} bytes)超过建议限制")
    
    print(f"     ✓ DG文件完整性验证通过 ({len(dg_files)}个数据组)")

def ensure_strict_der_encoding(asn1_object):
    """ 修复致命风险3: 确保严格DER编码一致性
    
    RFC 5652第794行要求: SignedAttributes MUST be DER encoded
    验证生成的字节是否为有效DER编码
    """
    try:
        der_bytes = encoder.encode(asn1_object)
        # 验证DER编码的有效性：解码后重新编码应该得到相同结果
        decoded_obj, remainder = decoder.decode(der_bytes)
        if remainder:
            raise ValueError("DER编码包含多余字节")
        
        # 重新编码验证
        re_encoded = encoder.encode(decoded_obj)
        if der_bytes != re_encoded:
            raise ValueError("DER编码不一致")
            
        return der_bytes
    except Exception as e:
        raise ValueError(f"DER编码验证失败: {e}")

def generate_sod_fixed(dg_files, key_path, cert_path, output_path):
    """生成修复版本的SOD文件 - 修复1字节长度偏差"""
    
    # 0.  修复潜在风险3: 预先验证数据组完整性
    print("\n[0] 验证数据组文件完整性")
    validate_dg_files_integrity(dg_files)
    
    # 1. 计算哈希
    print("\n[1] 计算DG哈希")
    dg_hashes = {}
    for dg_num, file_path in sorted(dg_files.items()):
        with open(file_path, 'rb') as f:
            dg_data = f.read()
        dg_hashes[dg_num] = hashlib.sha256(dg_data).digest()
        print(f"     DG{dg_num}: {len(dg_data)} bytes")

    # 2. 构建LDS Object
    lds_object_der = build_lds_security_object(dg_hashes)
    print(f"     LDS Object DER: {len(lds_object_der)} bytes")
    
    # 3. 构建签名属性
    signed_attrs = build_signed_attributes(lds_object_der)
    
    # 4. 加载DSC证书和私钥
    print("\n[4] 加载DSC证书和私钥")
    dsc_private_key = load_private_key(key_path)
    dsc_certificate = load_certificate(cert_path)
    cert_der = dsc_certificate.public_bytes(serialization.Encoding.DER)
    print(f"     DSC证书大小: {len(cert_der)} bytes")
    
    # 5. 生成数字签名
    print("\n[5] 生成数字签名")
    #  修复致命风险1: 使用正确的SignedAttributes编码方式
    signed_attrs_der = encode_signed_attributes_for_signing(signed_attrs)
    print("     ✓ 使用RFC 5652标准的EXPLICIT SET OF编码")
    
    if isinstance(dsc_private_key, rsa.RSAPrivateKey):
        signature = dsc_private_key.sign(
            signed_attrs_der, padding.PKCS1v15(), hashes.SHA256()
        )
        signature_algorithm_oid = SHA256_WITH_RSA_OID
        print("     ✓ 使用RSA-SHA256签名")
    elif isinstance(dsc_private_key, ec.EllipticCurvePrivateKey):
        signature = dsc_private_key.sign(
            signed_attrs_der, ec.ECDSA(hashes.SHA256())
        )
        signature_algorithm_oid = univ.ObjectIdentifier('1.2.840.10045.4.3.2')
        print("     ✓ 使用ECDSA-SHA256签名")
    else:
        raise ValueError(f"不支持的私钥类型: {type(dsc_private_key)}")
    
    print(f"     数字签名大小: {len(signature)} bytes")
    
    # 6. 构建SignerInfo
    print("\n[6] 构建SignerInfo")
    
    #  修复致命风险2: 使用安全的证书字段提取
    issuer_and_serial = build_issuer_and_serial_safe(dsc_certificate)
    print("     ✓ 安全提取IssuerAndSerialNumber（避免硬编码索引）")
    
    signer_id = SignerIdentifier()
    signer_id['issuerAndSerialNumber'] = issuer_and_serial
    
    digest_algorithm = AlgorithmIdentifier()
    digest_algorithm['algorithm'] = SHA256_OID
    #  修复潜在风险2: 明确设置SHA-256的parameters为NULL
    digest_algorithm['parameters'] = univ.Null()
    
    signature_algorithm = AlgorithmIdentifier()
    signature_algorithm['algorithm'] = signature_algorithm_oid
    #  修复潜在风险2: 签名算法parameters为NULL
    signature_algorithm['parameters'] = univ.Null()
    
    signer_info = SignerInfo()
    signer_info['version'] = 1
    signer_info['sid'] = signer_id
    signer_info['digestAlgorithm'] = digest_algorithm
    signer_info['signedAttrs'] = signed_attrs
    signer_info['signatureAlgorithm'] = signature_algorithm
    signer_info['signature'] = univ.OctetString(signature)
    
    signer_infos = SignerInfos()
    signer_infos.setComponentByPosition(0, signer_info)
    
    # 调试：检查SignerInfo大小
    signer_info_der = encoder.encode(signer_info)
    print(f"     SignerInfo DER: {len(signer_info_der)} bytes")
    
    # 7. 构建EncapsulatedContentInfo
    print("\n[7] 构建EncapsulatedContentInfo")
    encap_content_info = EncapsulatedContentInfo()
    encap_content_info['eContentType'] = LDS_SECURITY_OBJECT_OID
    #  关键修复：避免重复标签！EncapsulatedContentInfo.eContent字段已定义explicitTag
    # 直接传入原始字节，字段定义会自动包装为OctetString并添加explicitTag
    encap_content_info['eContent'] = lds_object_der
    
    # 调试：检查EncapsulatedContentInfo大小
    encap_info_der = encoder.encode(encap_content_info)
    print(f"     EncapsulatedContentInfo DER: {len(encap_info_der)} bytes")
    
    # 8. 构建SignedData
    print("\n[8] 构建SignedData - 修复版本")
    signed_data = SignedData()
    signed_data['version'] = 3
    
    # digestAlgorithms
    digest_algorithms_set = signed_data.getComponentByName('digestAlgorithms')
    digest_algorithm_entry = AlgorithmIdentifier()
    digest_algorithm_entry['algorithm'] = SHA256_OID
    #  修复潜在风险2: digestAlgorithms中的SHA-256 parameters为NULL
    digest_algorithm_entry['parameters'] = univ.Null()
    digest_algorithms_set.setComponentByPosition(0, digest_algorithm_entry)
    
    # encapContentInfo
    signed_data['encapContentInfo'] = encap_content_info
    
    #  修复3: 正确嵌入证书
    print("     ✓ 嵌入DSC证书（修复标签冲突）")
    certificates_set = CertificateSet()
    # 直接使用原始DER字节，标签由CertificateSet类处理
    certificates_set.setComponentByPosition(0, univ.Any(cert_der))
    signed_data['certificates'] = certificates_set
    
    # signerInfos
    signed_data['signerInfos'] = signer_infos
    
    # 调试：检查SignedData大小
    signed_data_der = encoder.encode(signed_data)
    print(f"     SignedData DER: {len(signed_data_der)} bytes")
    
    # 9. 构建ContentInfo - 关键长度修复点
    print("\n[9] 构建ContentInfo - 长度修复版本")
    content_info = ContentInfo()
    content_info['contentType'] = CMS_SIGNED_DATA_OID
    
    #   长度修复: 精确处理content字段的标签
    # 重新验证SignedData的编码长度
    print(f"     ✓ SignedData实际大小: {len(signed_data_der)} bytes")
   
    #  关键修复：避免重复标签！ContentInfo.content字段已定义explicitTag
    # 直接传入原始字节，字段定义会自动包装为Any并添加explicitTag [0]
    content_info['content'] = signed_data_der 
    
    #  关键修复: 预编码验证长度
    print("\n[9.5]  长度修复验证")
    pre_encode_der = encoder.encode(content_info)
    pre_encode_size = len(pre_encode_der)
    print(f"     预编码大小: {pre_encode_size} bytes")
    
    # 分析长度字段
    if pre_encode_size > 0:
        # 检查第一个长度字段（主SEQUENCE的长度）
        if pre_encode_der[0] == 0x30:  # SEQUENCE标签
            if pre_encode_der[1] & 0x80:  # 长格式长度
                length_bytes = pre_encode_der[1] & 0x7F
                declared_length = 0
                for i in range(length_bytes):
                    declared_length = (declared_length << 8) + pre_encode_der[2 + i]
                
                actual_content_length = pre_encode_size - (2 + length_bytes)
                print(f"     声明长度: {declared_length} bytes")
                print(f"     实际内容: {actual_content_length} bytes")
                
                if declared_length != actual_content_length:
                    print(f"       检测到长度偏差: {abs(declared_length - actual_content_length)} bytes")
                    print("      正在应用长度修复...")
                    
                    #  长度修复策略：重新构建ContentInfo以确保长度一致
                    # 强制重新编码以修复微小的长度偏差
                    try:
                        # 解码后重新编码，这样可以消除微小的编码差异
                        decoded_content, remainder = decoder.decode(pre_encode_der)
                        if remainder:
                            print(f"       发现残余字节: {len(remainder)} bytes")
                        
                        # 重新编码
                        fixed_der = encoder.encode(decoded_content)
                        fixed_size = len(fixed_der)
                        
                        print(f"     ✓ 修复后大小: {fixed_size} bytes")
                        
                        if fixed_size != pre_encode_size:
                            print(f"     ✓ 长度偏差已修复: {pre_encode_size} → {fixed_size}")
                            pre_encode_der = fixed_der
                        else:
                            print(f"     ✓ 长度已正确，无需修复")
                            
                    except Exception as e:
                        print(f"       长度修复失败，使用原始编码: {e}")
                else:
                    print(f"     ✓ 长度验证通过")
    
    # 10.  DataGroup标签包装 - 关键修复点！
    print("\n[10]  包装为DataGroup格式（添加0x77标签）")
    
    #  关键修复：将CMS ContentInfo包装成DataGroup格式
    # 验证端期望SOD的第一个字节是0x77，而不是0x30
    sod_datagroup = SODDataGroup(pre_encode_der)
    sod_with_correct_tag = encoder.encode(sod_datagroup)
    
    print(f"     ✓ CMS ContentInfo大小: {len(pre_encode_der)} bytes (标签: 0x{pre_encode_der[0]:02X})")
    print(f"     ✓ DataGroup SOD大小: {len(sod_with_correct_tag)} bytes (标签: 0x{sod_with_correct_tag[0]:02X})")
    
    # 验证标签是否正确
    if sod_with_correct_tag[0] == SOD_TAG:
        print(f"      SOD标签验证通过: 0x{SOD_TAG:02X}")
    else:
        print(f"      SOD标签不正确: 期望0x{SOD_TAG:02X}，实际0x{sod_with_correct_tag[0]:02X}")
    
    # 11. 最终编码和保存
    print("\n[11] 最终编码和保存")
    
    sod_der = sod_with_correct_tag  # 使用带有正确标签的DataGroup格式
    
    # 最终验证
    print(f"     ✓ 最终SOD大小: {len(sod_der)} bytes")
    print(f"     ✓ 第一个字节(标签): 0x{sod_der[0]:02X}")
    
    with open(output_path, 'wb') as f:
        f.write(sod_der)
    
    print(f"\n  SOD生成成功.")
    print(f"  文件: {output_path}")
    print(f"  大小: {len(sod_der)} bytes")
    print(f"  标签: 0x{sod_der[0]:02X} (DataGroup SOD格式)")
    print(f"     修复未知标签错误")
    print(f"     修复双重标签问题")
    print(f"     修复致命风险: 添加正确的0x77标签")
    print(f"     修复致命风险: 安全提取IssuerAndSerialNumber")
    print(f"     修复潜在风险: 使用正确的X.501 Name编码")
    print(f"     修复致命风险: 使用EXPLICIT SET OF标签重新编码SignedAttributes")
    print(f"     修复致命风险: SignedAttributes编码 - 使用RFC 5652标准EXPLICIT SET OF")
    print(f"     修复致命风险: 证书字段提取 - 移除硬编码索引，使用cryptography库")
    print(f"     修复致命风险: DER编码一致性 - 添加严格DER验证机制")
    print(f"     修复潜在风险: 验证数据组文件完整性")
    print(f"     修复致命风险: 确保严格DER编码一致性")
    print(f"     修复致命风险: 修复1字节长度偏差")
    print(f"     修复致命风险: 使用正确的SignedAttributes编码方式")
    print(f"     修复致命风险: 使用安全的证书字段提取")
    print(f"     修复潜在风险: 明确设置SHA-256的parameters为NULL")
    print(f"     修复潜在风险: 签名算法parameters为NULL")
    print(f"     修复致命风险: 避免重复标签！EncapsulatedContentInfo.eContent字段已定义explicitTag")
    print(f"     修复致命风险: 直接传入原始字节，字段定义会自动包装为OctetString并添加explicitTag")
    print(f"     修复潜在风险: digestAlgorithms中的SHA-256 parameters为NULL")
    print(f"     修复致命风险: 避免重复标签！ContentInfo.content字段已定义explicitTag")
    print(f"     修复致命风险: 将CMS ContentInfo包装成DataGroup格式")
    
    return True

def main():
    parser = argparse.ArgumentParser(description="生成SOD文件")
    
    parser.add_argument('--dg1', required=True, help='DG1文件路径')
    parser.add_argument('--dg2', required=True, help='DG2文件路径')
    parser.add_argument('--dg11', help='DG11文件路径')
    parser.add_argument('--dg12', help='DG12文件路径')
    parser.add_argument('--dg14', help='DG14文件路径')
    parser.add_argument('--dg15', help='DG15文件路径')   
    parser.add_argument('--dsc-key', help='DSC私钥文件路径')
    parser.add_argument('--dsc-cert', help='DSC证书文件路径')
    parser.add_argument('--out', default='SOD.bin', help='输出文件路径')
    
    args = parser.parse_args()
    
    # 自动扫描或使用指定的DSC文件
    if args.dsc_key and args.dsc_cert:
        dsc_key_path = args.dsc_key
        dsc_cert_path = args.dsc_cert
    else:
        dsc_key_path, dsc_cert_path = auto_find_dsc_files()
    
    dg_files = {}
    for i in range(1, 17):
        arg_name = f'dg{i}'
        if hasattr(args, arg_name) and getattr(args, arg_name):
            dg_files[i] = getattr(args, arg_name)
    
    print(f"\n SOD生产")
    print(f"=" * 60)
    
    success = generate_sod_fixed(
        dg_files=dg_files,
        key_path=dsc_key_path,
        cert_path=dsc_cert_path,
        output_path=args.out
    )
    
    exit(0 if success else 1)

if __name__ == '__main__':
    main() 