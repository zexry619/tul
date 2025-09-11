

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
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



#[derive(Debug)]
pub struct Request<R> {
    port: u16,
    host: String,

    reader: BufReader<R>,
}

impl<R: AsyncRead + Unpin> Request<R> {
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }
    pub fn hostname(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
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
    pub async fn parse<R: AsyncRead + Unpin>(pw_hash: &Vec<u8>, stream: R) -> std::io::Result<(Request<R>, Vec<u8>)> {
        let mut reader = BufReader::with_capacity(512, stream);

        let mut password_hash = [0u8; 28];
        reader.read_exact(&mut password_hash).await?;
        if password_hash != pw_hash.as_slice() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid password hash",
            ));
        }
        
        read_and_verify_crlf(&mut reader).await?;

        // 命令类型
        let mut command_buf = [0u8; 2];
        reader.read_exact(&mut command_buf).await?;
        match u16::from_be_bytes(command_buf) {
            1 => {},
            cmd => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unsupport command: {}", cmd),
                ));
            }
        };
        // 端口
        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        let mut addr_type = [0u8; 1];
        reader.read_exact(&mut addr_type).await?;

        let host = match addr_type[0] {
            1 => {
                // IPv4
                let mut ip_buf = [0u8; 4];
                reader.read_exact(&mut ip_buf).await?;
                Ipv4Addr::from(ip_buf).to_string()
            }
            4 => {
                // IPv6
                let mut ip_buf = [0u8; 16];
                reader.read_exact(&mut ip_buf).await?;
                Ipv6Addr::from(ip_buf).to_string()
            }
            3 => {
                // 域名
                let mut domain_len_buf = [0u8; 1];
                reader.read_exact(&mut domain_len_buf).await?;
                let domain_len = domain_len_buf[0] as usize;
                
                let mut domain_buf = vec![0u8; domain_len];
                reader.read_exact(&mut domain_buf).await?;
                
                let domain = String::from_utf8(domain_buf)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                domain
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown address type: {}", addr_type[0]),
                ));
            }
        };

        read_and_verify_crlf(&mut reader).await?;

        let payload = {
            let available = reader.buffer();
            available.to_vec()
        };
        Ok((Request{
            port,
            host,
            reader,
        }, payload))
    }
}