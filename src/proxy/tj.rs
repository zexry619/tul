

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::vec::Vec;
use sha2::Digest;


const CRLF: [u8; 2] = [b'\r', b'\n'];

#[derive(Debug)]
pub struct Server {}

#[derive(Debug)]
pub struct Client {
    pw: String,
}

impl Client {

    pub async fn establish<R: AsyncRead + AsyncWrite + Unpin>(&self, target_addr: SocketAddr, stream: &mut R) -> std::io::Result<()> { 
 
        // 构建 Trojan 请求头
        let request = self.build_payload(target_addr);
        
        // 发送请求头
        stream.write_all(&request).await?;
        
        // 读取服务器响应（可选，根据 Trojan 协议实现）
        let mut response_buf = [0u8; 2];
        stream.read_exact(&mut response_buf).await?;
        
        // 验证响应（通常 Trojan 服务器会返回 CRLF 表示成功）
        if &response_buf != CRLF.as_slice() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid server response",
            ));
        }
        // TODO
        Ok(())
    }
        
    fn build_payload(&self, target_addr: SocketAddr) -> Vec<u8> {
        let mut request = Vec::new();
        
        // 密码哈希（SHA224）
        let password_hash = sha2::Sha224::digest(self.pw.as_bytes());
        request.extend_from_slice(&password_hash);
        
        // CRLF
        request.extend_from_slice(CRLF.as_slice());
        
        // 命令类型 (1 = CONNECT)
        request.extend_from_slice(&1u16.to_be_bytes());
        
        // 目标端口
        request.extend_from_slice(&target_addr.port().to_be_bytes());
        
        // 地址类型和地址
        match target_addr.ip() {
            std::net::IpAddr::V4(ipv4) => {
                request.push(1); // IPv4
                request.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                request.push(4); // IPv6
                request.extend_from_slice(&ipv6.octets());
            }
        }
        
        // 最后的 CRLF
        request.extend_from_slice(CRLF.as_slice());
        
        request
    }

}


async fn read_and_verify_crlf<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<()> {
    let mut crlf_suffix = [0u8; 2];
    reader.read_exact(&mut crlf_suffix).await?;
    
    if crlf_suffix != CRLF {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Missing CRLF suffix",
        ));
    }
    Ok(())
}

impl Server {
    pub async fn parse<R: AsyncRead + Unpin>(pw_hash: &Vec<u8>, stream: &mut R) -> std::io::Result<(String, u16)> {
    
        let mut password_hash = [0u8; 56];
        stream.read_exact(&mut password_hash).await?;
        if &password_hash != pw_hash.as_slice() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid hash, expected: {:?}, got: {:?}", 
                    String::from_utf8_lossy(pw_hash.as_slice()), 
                    String::from_utf8_lossy(&password_hash)),
            ));
        }
        
        // Read CLRF
        stream.read_u16().await?;

        // Extract command
        match stream.read_u8().await? {
            1 => {},
            cmd => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unsupport command: {}", cmd),
                ));
            }
        };

        // Read address type
        let atype = stream.read_u8().await?;

        // Get address size and address object
        let host = match atype {
            1 => Ipv4Addr::from(stream.read_u32().await?).to_string(),
            4 => Ipv6Addr::from(stream.read_u128().await?).to_string(),
            3 => {
                // Read domain name size
                let size = stream.read_u8().await? as usize;

                // Read domain name context
                let mut domain_buf = vec![0u8; size];
                stream.read_exact(&mut domain_buf).await?;
                String::from_utf8(domain_buf)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            }
            _ => return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown address type: {atype}"),
                )),
        };

        // Read port number
        let port = stream.read_u16().await?;

        // Read CLRF
        stream.read_u16().await?;

        Ok((host,  port))
    }
}