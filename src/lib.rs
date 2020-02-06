use failure::{format_err, Error};
use regex::Regex;
use std::path::Path;
use tsunami::Session;

lazy_static::lazy_static! {
    static ref IFACE_REGEX: Regex = Regex::new(r"[0-9]+:\s+([a-z]+[0-9]+)\s+inet").unwrap();
}

pub struct Node<'a, 'b> {
    pub ssh: &'a Session,
    pub name: &'b str,
    pub ip: &'b str,
    pub user: &'b str,
}

pub fn aws_to_local(
    alg: &str,
    out_dir: &Path,
    log: &slog::Logger,
    sender: &Node,
) -> Result<(), Error> {
    let sender_home = get_home(sender.ssh, sender.user)?;

    let (cmd, flag) = start_alg(alg, &sender_home);

    if let Some(c) = cmd {
        sender.ssh.cmd(&c).map(|_| ())?;
    }

    // iperf receiver
    let iperf_cmd = format!("screen -d -m bash -c \"~/tools/iperf/src/iperf -s -p 5001 --reverse -Z {} > ~/iperf_server.out 2> ~/iperf_server.out\"", flag);
    slog::debug!(log, "starting remote iperf"; "from" => sender.name);
    sender.ssh.cmd(&iperf_cmd).map(|_| ())?;

    // bmon receiver
    slog::debug!(log, "starting bmon"; "from" => sender.name);
    sender
        .ssh
        .cmd(&format!(
            "screen -d -m bash -c \"stdbuf -o0 bmon -p ens5 -b -o format:fmt='\\$(element:name) \\$(attr:rxrate:bytes)\n' > {}/bmon.out\"",
            sender_home
        ))
        .map(|_| ())?;

    // wait to start
    std::thread::sleep(std::time::Duration::from_secs(5));

    // iperf
    slog::debug!(log, "starting local iperf"; "from" => sender.name, "alg" => &flag);
    let iperf_out = std::process::Command::new("./cc-exp-tools/iperf/src/iperf")
        .args(&[
            "-c",
            sender.ip,
            "--reverse",
            "-p",
            "5001",
            "-t",
            "150",
            "-i",
            "1",
            "-Z",
            &flag,
        ])
        .output()?;

    // write iperf_out to ./iperf_client.log
    use std::io::Write;
    let mut f = std::fs::File::create("./iperf_client.log")?;
    f.write_all(&iperf_out.stdout)?;

    get_file(
        sender.ssh,
        Path::new(&format!("{}/iperf_server.out", sender_home)),
        &out_dir.join("./iperf_server.log"),
    )?;
    get_file(
        sender.ssh,
        Path::new(&format!("{}/bmon.out", sender_home)),
        &out_dir.join("./bmon.log"),
    )?;

    Ok(())
}

// (start ccp cmd, -Z {})
pub fn start_alg(name: &str, sender_home: &str) -> (Option<String>, String) {
    match name {
        "cubic" | "bbr" | "vegas" => (None, name.to_string()),
        "copa" => (
            Some(format!(
                "screen -d -m bash -c \"cd {}/tools/ccp_copa && sudo ./target/release/copa --ipc=netlink 2>&1 > {}/copa.log\"",
                sender_home, sender_home
            )),
            "ccp".to_string(),
        ),
        "nimbus" => (
            Some(format!(
                "screen -d -m bash -c \"cd {}/tools/nimbus && sudo ./target/release/nimbus --ipc=netlink --bw_est_mode=true --xtcp_flows=1 --flow_mode=Delay --loss_mode=Cubic --uest=384 2>&1 > {}/nimbus.log\"",
                sender_home, sender_home
            )),
            "ccp".to_string(),
        ),
        _ => unreachable!(),
    }
}

pub fn get_home(ssh: &Session, user: &str) -> Result<String, Error> {
    ssh.cmd(&format!("echo ~{}", user))
        .map(|(out, _)| out.trim().to_string())
}

pub fn iface_name(ip_addr_out: (String, String)) -> Result<String, Error> {
    ip_addr_out
        .0
        .lines()
        .filter_map(|l| Some(IFACE_REGEX.captures(l)?.get(1)?.as_str().to_string()))
        .filter(|l| match l.as_str() {
            "lo" => false,
            _ => true,
        })
        .next()
        .ok_or_else(|| format_err!("No matching interfaces"))
}

pub fn get_iface_name(node: &Session) -> Result<String, Error> {
    node.cmd("bash -c \"ip -o addr | awk '{print $2}'\"")
        .and_then(iface_name)
}

pub fn install_basic_packages(ssh: &Session) -> Result<(), Error> {
    let mut count = 0;
    loop {
        count += 1;
        let res = (|| -> Result<(), Error> {
            ssh.cmd("sudo apt update")
                .map(|(_, _)| ())
                .map_err(|e| e.context("apt update failed"))?;
            ssh.cmd("sudo apt update && sudo DEBIAN_FRONTEND=noninteractive apt install -y build-essential bmon coreutils git automake autoconf libtool")
                .map(|(_, _)| ())
                .map_err(|e| e.context("apt install failed"))?;
            Ok(())
        })();

        if let Ok(_) = res {
            return res;
        } else {
            println!("apt failed: {:?}", res);
        }

        if count > 15 {
            return res;
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

pub fn get_tools(ssh: &Session) -> Result<(), Error> {
    ssh.cmd("sudo sysctl -w net.ipv4.ip_forward=1")
        .map(|(_, _)| ())?;
    ssh.cmd("sudo sysctl -w net.ipv4.tcp_wmem=\"4096000 50331648 50331648\"")
        .map(|(_, _)| ())?;
    ssh.cmd("sudo sysctl -w net.ipv4.tcp_rmem=\"4096000 50331648 50331648\"")
        .map(|(_, _)| ())?;
    if let Err(_) = ssh
        .cmd("git clone --recursive https://github.com/bundler-project/tools")
        .map(|(_, _)| ())
    {
        ssh.cmd("ls ~/tools").map(|(_, _)| ())?;
    }
    ssh.cmd("cd ~/tools/bundler && git checkout no_dst_ip")
        .map(|(_, _)| ())?;

    ssh.cmd("make -C tools").map(|(_, _)| ())
}

pub fn get_file(ssh: &Session, remote_path: &Path, local_path: &Path) -> Result<(), Error> {
    ssh.scp_recv(std::path::Path::new(remote_path))
        .map_err(Error::from)
        .and_then(|(mut channel, _)| {
            let mut out = std::fs::File::create(local_path)?;
            std::io::copy(&mut channel, &mut out)?;
            Ok(())
        })
        .map_err(|e| e.context(format!("scp {:?}", remote_path)))?;
    Ok(())
}

pub fn reset(sender: &Node, receiver: &Node, log: &slog::Logger) {
    let sender_ssh = sender.ssh;
    pkill(sender_ssh, "udping_client", &log);
    pkill(sender_ssh, "iperf", &log);
    pkill(sender_ssh, "bmon", &log);
    sender_ssh.cmd("sudo pkill -9 nimbus").unwrap_or_default();
    sender_ssh.cmd("sudo pkill -9 ccp_copa").unwrap_or_default();
    let receiver_ssh = receiver.ssh;
    pkill(receiver_ssh, "udping_server", &log);
    pkill(receiver_ssh, "iperf", &log);
    pkill(receiver_ssh, "bmon", &log);
}

pub fn pkill(ssh: &Session, procname: &str, _log: &slog::Logger) {
    let cmd = format!("pkill -9 {}", procname);
    ssh.cmd(&cmd).unwrap_or_default();
    //if let Err(e) = ssh.cmd(&cmd) {
    //    slog::warn!(log, "pkill failed";
    //        "cmd" => procname,
    //        "error" => ?e,
    //    );
    //}
}

#[cfg(test)]
mod tests {
    #[test]
    fn iface() {
        let out = r"1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: em1    inet 18.26.5.2/23 brd 18.26.5.255 scope global em1\       valid_lft forever preferred_lft forever".to_string();
        assert_eq!(super::iface_name((out, String::new())).unwrap(), "em1");
    }
}
