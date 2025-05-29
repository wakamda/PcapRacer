use std::process::{Command, Stdio};
use std::fs::File;

pub fn run_tshark(input_pcap: &str, output_tsv: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("tshark")
        .arg("-r").arg(input_pcap)
        .arg("-T").arg("fields")
        .arg("-e").arg("ip.src")
        .arg("-e").arg("ip.dst")
        .arg("-e").arg("ip.len")
        .arg("-e").arg("dns.qry.name")
        .arg("-e").arg("http.host")
        .arg("-e").arg("ssl.handshake.extensions_server_name")
        // .arg("-E").arg("header=y")
        .arg("-E").arg("separator=\t")
        .arg("-E").arg("occurrence=f")
        .stdout(Stdio::piped())
        .spawn()?;

    let output_file = File::create(output_tsv)?;
    let mut writer = std::io::BufWriter::new(output_file);

    if let Some(mut stdout) = child.stdout.take() {
        std::io::copy(&mut stdout, &mut writer)?;
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(format!("❌ tshark命令执行失败").into());
    }

    Ok(())
}
